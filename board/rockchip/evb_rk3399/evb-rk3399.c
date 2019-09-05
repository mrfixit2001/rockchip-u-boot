/*
 * (C) Copyright 2016 Rockchip Electronics Co., Ltd
 *
 * SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <dm.h>
#include <ram.h>
#include <dm/pinctrl.h>
#include <dm/uclass-internal.h>
#include <asm/arch/periph.h>
#include <power/regulator.h>
#include <usb.h>
#include <dwc3-uboot.h>
#include <spl.h>
#include <asm/gpio.h>

DECLARE_GLOBAL_DATA_PTR;

static void rk3399_force_sdmmc_power_on(void)
{
/*
	// Disabled but left in place in case we need to use it in the future
	ofnode node;
	struct gpio_desc sdmmc_pwr_gpio;

	printf("%s: trying to force sdmmc power on\n", __func__);

	node = ofnode_path("/forced-gpios");
	if (!ofnode_valid(node)) {
		printf("%s: no /forced-gpios node?\n", __func__);
		return;
	}

	if (gpio_request_by_name_nodev(node, "sdmmc-pwr-gpio", 0,
				       &sdmmc_pwr_gpio, GPIOD_IS_OUT)) {
		printf("%s: could not find a /forced-gpios/sdmmc-pwr-gpio\n", __func__);
		return;
	}

	dm_gpio_set_value(&sdmmc_pwr_gpio, 1);
*/
}

int rk_board_init(void)
{
	struct udevice *pinctrl, *regulator;
	int ret;

	/*
	 * The PWM does not have decicated interrupt number in dts and can
	 * not get periph_id by pinctrl framework, so let's init them here.
	 * The PWM2 and PWM3 are for pwm regulators.
	 */
	ret = uclass_get_device(UCLASS_PINCTRL, 0, &pinctrl);
	if (ret) {
		printf("%s: Cannot find pinctrl device\n", __func__);
	} else {
		ret = pinctrl_request_noflags(pinctrl, PERIPH_ID_PWM2);
		if (ret) {
			printf("%s PWM2 pinctrl init fail!\n", __func__);
		}
	}

	// vcc5v0_host Regulator
	ret = regulator_get_by_platname("vcc5v0_host", &regulator);
	if (ret) {
		printf("%s vcc5v0_host init fail! ret %d\n", __func__, ret);
	} else {
		ret = regulator_set_enable(regulator, true);
		if (ret) {
			printf("%s vcc5v0_host enable fail!\n", __func__);
		}
	}

	// vcc5v0_usb3_host Regulator
	ret = regulator_get_by_platname("vcc5v0_usb3_host", &regulator);
	if (ret) {
		printf("%s vcc5v0_usb3_host init fail! ret %d\n", __func__, ret);
	} else {
		ret = regulator_set_enable(regulator, true);
		if (ret) {
			printf("%s vcc5v0_usb3_host enable fail!\n", __func__);
		}
	}
/*
	// vcc12v_pcie Regulator
	ret = regulator_get_by_platname("vcc12v_pcie", &regulator);
	if (ret) {
		printf("%s vcc12v_pcie init fail! ret %d\n", __func__, ret);
	} else {
		ret = regulator_set_enable(regulator, true);
		if (ret) {
			printf("%s vcc12v_pcie enable fail!\n", __func__);
		}
	}
*/

	// vcc3v0_sdio Regulator
	ret = regulator_get_by_platname("vcc3v0_sdio", &regulator);
	if (ret) {
		printf("%s vcc3v0_sdio init fail! ret %d\n", __func__, ret);
	} else {
		ret = regulator_set_value(regulator, 3000000);
		if (ret) {
			printf("%s: vcc3v0_sdio cannot set regulator value %d\n", __func__, ret);
		}
		ret = regulator_set_enable(regulator, true);
		if (ret) {
			printf("%s vcc3v0_sdio enable fail!\n", __func__);
		}
	}


	ret = regulators_enable_boot_on(true);
	if (ret)
		printf("%s: Cannot enable boot on regulator\n", __func__);

	rk3399_force_sdmmc_power_on();

	return 0;
}

#ifdef CONFIG_USB_DWC3
static struct dwc3_device dwc3_device_data = {
	.maximum_speed = USB_SPEED_HIGH,
	.base = 0xfe800000,
	.dr_mode = USB_DR_MODE_PERIPHERAL,
	.index = 0,
	.dis_u2_susphy_quirk = 1,
	.usb2_phyif_utmi_width = 16,
};

int usb_gadget_handle_interrupts(void)
{
	dwc3_uboot_handle_interrupt(0);
	return 0;
}

int board_usb_init(int index, enum usb_init_type init)
{
	return dwc3_uboot_init(&dwc3_device_data);
}
#endif
