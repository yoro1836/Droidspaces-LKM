/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_DEVTMPFS_PORT_H
#define DS_DEVTMPFS_PORT_H
#include <linux/device.h>
int ds_devtmpfs_start(void);
void ds_devtmpfs_stop(void);
int ds_devtmpfs_create_node(struct device *dev);
int ds_devtmpfs_delete_node(struct device *dev);
int ds_device_add(struct device *dev);
void ds_device_del(struct device *dev);
int ds_hooks_prepare(void);
int ds_hooks_install(void);
int ds_device_add_original(struct device *dev);
void ds_device_del_original(struct device *dev);
/* native device_add/device_del in either hook mode */
int ds_device_add_native(struct device *dev);
void ds_device_del_native(struct device *dev);
#endif
