// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#ifndef __BLUERDMA_ETHERNET_H__
#define __BLUERDMA_ETHERNET_H__

#include <linux/device.h>
#include "bluerdma.h"

int bluerdma_create_netdev(struct bluerdma_dev *dev, int id);
void bluerdma_destroy_netdev(struct bluerdma_dev *dev);
void bluerdma_init_sysfs_attrs(struct bluerdma_dev *dev);
ssize_t bluerdma_show_gids(struct device *dev, struct device_attribute *attr,
			   char *buf);
ssize_t bluerdma_show_mac(struct device *dev, struct device_attribute *attr,
			  char *buf);

#endif // __BLUERDMA_ETHERNET_H__
