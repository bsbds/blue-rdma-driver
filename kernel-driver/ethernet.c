// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>

#include "bluerdma.h"
#include "ethernet.h"

static netdev_tx_t bluerdma_netdev_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct bluerdma_dev *dev = netdev_priv(netdev);
	unsigned long flags;

	pr_debug("bluerdma_netdev_xmit: sending packet of length %d\n",
		 skb->len);

	spin_lock_irqsave(&dev->tx_lock, flags);

	/* TODO: DMA the packet to hardware */

	netdev->stats.tx_packets++;
	netdev->stats.tx_bytes += skb->len;

	spin_unlock_irqrestore(&dev->tx_lock, flags);

	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static int bluerdma_netdev_open(struct net_device *netdev)
{
	struct bluerdma_dev *dev = netdev_priv(netdev);

	pr_info("bluerdma_netdev_open: bringing up interface %s\n",
		netdev->name);

	netif_carrier_on(netdev);
	netif_start_queue(netdev);
	napi_enable(&dev->napi);

	dev->state = IB_PORT_ACTIVE;

	return 0;
}

static int bluerdma_netdev_stop(struct net_device *netdev)
{
	struct bluerdma_dev *dev = netdev_priv(netdev);

	pr_info("bluerdma_netdev_stop: shutting down interface %s\n",
		netdev->name);

	napi_disable(&dev->napi);
	netif_stop_queue(netdev);
	netif_carrier_off(netdev);

	dev->state = IB_PORT_DOWN;

	return 0;
}

static int bluerdma_netdev_change_mtu(struct net_device *netdev, int new_mtu)
{
	pr_info("bluerdma_netdev_change_mtu: changing MTU from %d to %d\n",
		netdev->mtu, new_mtu);

	netdev->mtu = new_mtu;
	return 0;
}

static int bluerdma_napi_poll(struct napi_struct *napi, int budget)
{
	int work_done = 0;

	/* TODO: process received packets */

	napi_complete_done(napi, work_done);

	return work_done;
}

static const struct net_device_ops bluerdma_netdev_ops = {
	.ndo_open = bluerdma_netdev_open,
	.ndo_stop = bluerdma_netdev_stop,
	.ndo_start_xmit = bluerdma_netdev_xmit,
	.ndo_change_mtu = bluerdma_netdev_change_mtu,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr = eth_validate_addr,
};

static void bluerdma_netdev_setup(struct net_device *netdev)
{
	struct bluerdma_dev *dev = netdev_priv(netdev);

	netdev->netdev_ops = &bluerdma_netdev_ops;

	netdev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			      NETIF_F_RXCSUM;
	netdev->features = netdev->hw_features;

	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = ETH_MAX_MTU;
	netdev->mtu = BLUERDMA_DEFAULT_MTU;

	netif_napi_add(netdev, &dev->napi, bluerdma_napi_poll);

	/* TODO: Read MAC address from device */
	eth_hw_addr_random(netdev);

	spin_lock(&dev->mac_lock);
	memcpy(dev->mac_addr, netdev->dev_addr, ETH_ALEN);
	spin_unlock(&dev->mac_lock);

	spin_lock_init(&dev->tx_lock);
	spin_lock_init(&dev->mac_lock);

	netif_carrier_off(netdev);
}

/* Convert MAC address to EUI-64 format for GID */
static void mac_to_eui64_gid(u8 *mac, union ib_gid *gid)
{
	/* Set the link-local prefix (fe80::) */
	gid->raw[0] = 0xfe;
	gid->raw[1] = 0x80;
	memset(&gid->raw[2], 0, 6);

	/* Convert MAC to EUI-64 format:
	 * MAC: XX:XX:XX:YY:YY:YY becomes XX:XX:XX:FF:FE:YY:YY:YY
	 * and flip the 7th bit of the first byte
	 */
	gid->raw[8] = mac[0] ^ 0x02; /* Flip universal/local bit */
	gid->raw[9] = mac[1];
	gid->raw[10] = mac[2];
	gid->raw[11] = 0xFF;
	gid->raw[12] = 0xFE;
	gid->raw[13] = mac[3];
	gid->raw[14] = mac[4];
	gid->raw[15] = mac[5];
}

static void bluerdma_init_gid_table(struct bluerdma_dev *dev)
{
	int i;

	spin_lock_init(&dev->gid_lock);

	for (i = 0; i < BLUERDMA_GID_TABLE_SIZE; i++) {
		memset(&dev->gid_table[i], 0,
		       sizeof(struct bluerdma_gid_entry));
		dev->gid_table[i].valid = false;
	}

	/* Initialize the default GID (index 0) based on MAC address */
	if (dev->netdev) {
		mac_to_eui64_gid(dev->mac_addr, &dev->gid_table[0].gid);

		dev->gid_table[0].valid = true;

		pr_debug("Initialized default GID for device %d: %pI6\n",
			 dev->id, dev->gid_table[0].gid.raw);
	}
}

int bluerdma_create_netdev(struct bluerdma_dev *dev, int id)
{
	struct net_device *netdev;
	int ret;

	netdev = alloc_etherdev(sizeof(struct bluerdma_dev));
	if (!netdev) {
		pr_err("Failed to allocate netdev for device %d\n", id);
		return -ENOMEM;
	}

	snprintf(netdev->name, IFNAMSIZ, "blue%d", id);

	struct bluerdma_dev *priv = netdev_priv(netdev);

	priv->id = id;
	priv->netdev = netdev;

	dev->netdev = netdev;

	bluerdma_netdev_setup(netdev);

	bluerdma_init_gid_table(dev);

	ret = register_netdev(netdev);
	if (ret) {
		pr_err("Failed to register netdev for device %d: %d\n", id,
		       ret);
		free_netdev(netdev);
		dev->netdev = NULL;
		return ret;
	}

	pr_info("Registered network device %s for RDMA device %d\n",
		netdev->name, id);
	return 0;
}

void bluerdma_destroy_netdev(struct bluerdma_dev *dev)
{
	if (dev->netdev) {
		unregister_netdev(dev->netdev);
		free_netdev(dev->netdev);
		dev->netdev = NULL;
	}
}

ssize_t bluerdma_show_gids(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct bluerdma_dev *bdev =
		to_bdev(container_of(dev, struct ib_device, dev));
	ssize_t len = 0;
	int i;

	spin_lock(&bdev->gid_lock);

	for (i = 0; i < BLUERDMA_GID_TABLE_SIZE; i++) {
		if (bdev->gid_table[i].valid) {
			len += scnprintf(buf + len, PAGE_SIZE - len, "%pI6\n",
					 bdev->gid_table[i].gid.raw);
		}
	}

	spin_unlock(&bdev->gid_lock);

	return len;
}

ssize_t bluerdma_show_mac(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct bluerdma_dev *bdev =
		to_bdev(container_of(dev, struct ib_device, dev));
	ssize_t len;

	if (bdev->netdev) {
		len = scnprintf(buf, PAGE_SIZE, "%pM\n",
				bdev->netdev->dev_addr);
	} else {
		spin_lock(&bdev->mac_lock);
		len = scnprintf(buf, PAGE_SIZE, "%pM\n", bdev->mac_addr);
		spin_unlock(&bdev->mac_lock);
	}

	return len;
}

void bluerdma_init_sysfs_attrs(struct bluerdma_dev *dev)
{
	sysfs_attr_init(&dev->gids_attr.attr);
	dev->gids_attr.attr.name = "gids";
	dev->gids_attr.attr.mode = 0444;
	dev->gids_attr.show = bluerdma_show_gids;
	dev->gids_attr.store = NULL;

	sysfs_attr_init(&dev->mac_attr.attr);
	dev->mac_attr.attr.name = "mac";
	dev->mac_attr.attr.mode = 0444;
	dev->mac_attr.show = bluerdma_show_mac;
	dev->mac_attr.store = NULL;
}
