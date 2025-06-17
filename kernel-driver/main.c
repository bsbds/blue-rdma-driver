// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>

#include "bluerdma.h"
#include "verbs.h"

MODULE_AUTHOR("Hange Shen <Foreverhighness@gmail.com>");
MODULE_DESCRIPTION("DatenLord RDMA adapter driver");
MODULE_LICENSE("Dual BSD/GPL");

#pragma region ib device

#define N_TESTING 2
static struct bluerdma_dev *testing_dev[N_TESTING] = {};

#pragma region netdev ops

static netdev_tx_t bluerdma_netdev_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct bluerdma_dev *dev = netdev_priv(netdev);
	unsigned long flags;

	pr_debug("bluerdma_netdev_xmit: sending packet of length %d\n",
		 skb->len);

	spin_lock_irqsave(&dev->tx_lock, flags);

	/* In a real driver, we would DMA the packet to hardware here */

	/* Update statistics */
	netdev->stats.tx_packets++;
	netdev->stats.tx_bytes += skb->len;

	spin_unlock_irqrestore(&dev->tx_lock, flags);

	/* Free the SKB */
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static int bluerdma_netdev_open(struct net_device *netdev)
{
	struct bluerdma_dev *dev = netdev_priv(netdev);

	pr_info("bluerdma_netdev_open: bringing up interface %s\n",
		netdev->name);

	/* Start the network interface */
	netif_carrier_on(netdev);
	netif_start_queue(netdev);
	napi_enable(&dev->napi);

	/* Update RDMA port state */
	dev->state = IB_PORT_ACTIVE;

	return 0;
}

static int bluerdma_netdev_stop(struct net_device *netdev)
{
	struct bluerdma_dev *dev = netdev_priv(netdev);

	pr_info("bluerdma_netdev_stop: shutting down interface %s\n",
		netdev->name);

	/* Stop the network interface */
	napi_disable(&dev->napi);
	netif_stop_queue(netdev);
	netif_carrier_off(netdev);

	/* Update RDMA port state */
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
	struct bluerdma_dev *dev =
		container_of(napi, struct bluerdma_dev, napi);
	int work_done = 0;

	/* In a real driver, we would process received packets here */

	/* If we processed all packets, complete NAPI */
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

	/* Set Ethernet device operations */
	netdev->netdev_ops = &bluerdma_netdev_ops;

	/* Set Ethernet device features */
	netdev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			      NETIF_F_RXCSUM;
	netdev->features = netdev->hw_features;

	/* Set MTU limits */
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = ETH_MAX_MTU;
	netdev->mtu = BLUERDMA_DEFAULT_MTU;

	/* Initialize NAPI */
	netif_napi_add(netdev, &dev->napi, bluerdma_napi_poll);

	/* Set MAC address */
	eth_hw_addr_random(netdev);
	memcpy(dev->mac_addr, netdev->dev_addr, ETH_ALEN);

	/* Initialize locks */
	spin_lock_init(&dev->tx_lock);
	
	/* Start with carrier off - will be turned on when opened */
	netif_carrier_off(netdev);
}

static void bluerdma_init_gid_table(struct bluerdma_dev *dev)
{
	int i;
	
	spin_lock_init(&dev->gid_lock);
	
	for (i = 0; i < BLUERDMA_GID_TABLE_SIZE; i++) {
		memset(&dev->gid_table[i], 0, sizeof(struct bluerdma_gid_entry));
		dev->gid_table[i].valid = false;
	}
	
	/* Initialize the default GID (index 0) based on MAC address */
	if (dev->netdev) {
		/* Create an IPv6-mapped IPv4 GID based on the MAC address */
		memset(dev->gid_table[0].gid.raw, 0, 10);
		dev->gid_table[0].gid.raw[10] = 0xff;
		dev->gid_table[0].gid.raw[11] = 0xff;
		
		/* Use the last 4 bytes of the MAC address as the IPv4 address */
		memcpy(&dev->gid_table[0].gid.raw[12], &dev->mac_addr[2], 4);
		
		dev->gid_table[0].valid = true;
		
		pr_debug("Initialized default GID for device %d: %pI6\n", 
			 dev->id, dev->gid_table[0].gid.raw);
	}
}

static int bluerdma_create_netdev(struct bluerdma_dev *dev, int id)
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
	
	/* Initialize GID table after MAC address is set */
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

static void bluerdma_destroy_netdev(struct bluerdma_dev *dev)
{
	if (dev->netdev) {
		unregister_netdev(dev->netdev);
		free_netdev(dev->netdev);
		dev->netdev = NULL;
	}
}

#pragma endregion netdev ops

// Show function for GIDs
static ssize_t bluerdma_show_gids(struct device *dev, 
                                 struct device_attribute *attr,
                                 char *buf)
{
    struct bluerdma_dev *bdev = to_bdev(container_of(dev, struct ib_device, dev));
    ssize_t len = 0;
    int i;
    
    spin_lock(&bdev->gid_lock);
    
    for (i = 0; i < BLUERDMA_GID_TABLE_SIZE; i++) {
        if (bdev->gid_table[i].valid) {
            len += scnprintf(buf + len, PAGE_SIZE - len, 
                           "%d: %pI6\n", i, bdev->gid_table[i].gid.raw);
        }
    }
    
    spin_unlock(&bdev->gid_lock);
    
    return len;
}

// Show function for MAC address
static ssize_t bluerdma_show_mac(struct device *dev, 
                                struct device_attribute *attr,
                                char *buf)
{
    struct bluerdma_dev *bdev = to_bdev(container_of(dev, struct ib_device, dev));
    
    return scnprintf(buf, PAGE_SIZE, "%pM\n", bdev->mac_addr);
}

// Initialize sysfs attributes
static void bluerdma_init_sysfs_attrs(struct bluerdma_dev *dev)
{
    // Initialize GIDs attribute
    sysfs_attr_init(&dev->gids_attr.attr);
    dev->gids_attr.attr.name = "gids";
    dev->gids_attr.attr.mode = 0444; // read-only
    dev->gids_attr.show = bluerdma_show_gids;
    dev->gids_attr.store = NULL;
    
    // Initialize MAC attribute
    sysfs_attr_init(&dev->mac_attr.attr);
    dev->mac_attr.attr.name = "mac";
    dev->mac_attr.attr.mode = 0444; // read-only
    dev->mac_attr.show = bluerdma_show_mac;
    dev->mac_attr.store = NULL;
}

static int bluerdma_new_testing(void)
{
	struct bluerdma_dev *dev;
	int i, ret;

	for (i = 0; i < N_TESTING; i++) {
		dev = ib_alloc_device(bluerdma_dev, ibdev);
		if (!dev) {
			pr_err("ib_alloc_device failed for index %d\n", i);
			while (--i >= 0) {
				if (testing_dev[i]->netdev)
					bluerdma_destroy_netdev(testing_dev[i]);
				ib_dealloc_device(&testing_dev[i]->ibdev);
				testing_dev[i] = NULL;
			}
			return -ENOMEM;
		}
		testing_dev[i] = dev;
		dev->id = i;
		pr_info("ib_alloc_device ok for index %d\n", dev->id);

		/* Create network device for this RDMA device */
		ret = bluerdma_create_netdev(dev, i);
		if (ret) {
			pr_err("bluerdma_create_netdev failed for index %d\n",
			       i);
			ib_dealloc_device(&dev->ibdev);
			while (--i >= 0) {
				if (testing_dev[i]->netdev)
					bluerdma_destroy_netdev(testing_dev[i]);
				ib_dealloc_device(&testing_dev[i]->ibdev);
				testing_dev[i] = NULL;
			}
			return ret;
		}
	}

	return 0;
}

static void bluerdma_free_testing(void)
{
	int i;
	for (i = 0; i < N_TESTING; i++) {
		if (testing_dev[i]) {
			if (testing_dev[i]->netdev)
				bluerdma_destroy_netdev(testing_dev[i]);
			ib_dealloc_device(&testing_dev[i]->ibdev);
			testing_dev[i] = NULL;
			pr_info("ib_dealloc_device ok for index %d\n", i);
		}
	}
}

static const struct ib_device_ops bluerdma_device_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_UNKNOWN,
	.uverbs_abi_ver = 1,

	// mandatory methods <https://elixir.bootlin.com/linux/v6.8/source/drivers/infiniband/core/device.c#L267>
	.query_device = bluerdma_query_device,
	.query_port = bluerdma_query_port,

	.alloc_pd = bluerdma_alloc_pd,
	.dealloc_pd = bluerdma_dealloc_pd,

	.create_qp = bluerdma_create_qp,
	.modify_qp = bluerdma_modify_qp,
	.destroy_qp = bluerdma_destroy_qp,

	.post_send = bluerdma_post_send,
	.post_recv = bluerdma_post_recv,

	.create_cq = bluerdma_create_cq,
	.destroy_cq = bluerdma_destroy_cq,
	.poll_cq = bluerdma_poll_cq,

	.req_notify_cq = bluerdma_req_notify_cq,

	.get_dma_mr = bluerdma_get_dma_mr,
	.reg_user_mr = bluerdma_reg_user_mr,
	.dereg_mr = bluerdma_dereg_mr,

	.get_port_immutable = bluerdma_get_port_immutable,
	// optional methods

	// uverbs required methods
	.alloc_ucontext = bluerdma_alloc_ucontext,
	.dealloc_ucontext = bluerdma_dealloc_ucontext,

	.query_gid = bluerdma_query_gid,
	.query_pkey = bluerdma_query_pkey,
	.add_gid = bluerdma_add_gid,
	.del_gid = bluerdma_del_gid,

	// init size
	// INIT_RDMA_OBJ_SIZE(ib_ah, bluerdma_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, bluerdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, bluerdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_qp, bluerdma_qp, ibqp),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, bluerdma_ucontext, ibuc),
	// INIT_RDMA_OBJ_SIZE(ib_srq, bluerdma_srq, ibsrq),
	// INIT_RDMA_OBJ_SIZE(ib_mw, bluerdma_mw, ibmw),
};

static int bluerdma_ib_device_add(struct pci_dev *pdev)
{
	struct ib_device *ibdev;
	int ret, i;

	ret = bluerdma_new_testing();
	if (ret) {
		pr_err("bluerdma_new_testing failed\n");
		return ret;
	}

	for (i = 0; i < N_TESTING; i++) {
		ibdev = &testing_dev[i]->ibdev;

		strscpy(ibdev->node_desc, "bluerdma", sizeof(ibdev->node_desc));

		ibdev->node_type = RDMA_NODE_RNIC;
		ibdev->phys_port_cnt = 1;
		ibdev->num_comp_vectors = num_possible_cpus();
		ibdev->local_dma_lkey = 0;

		ib_set_device_ops(ibdev, &bluerdma_device_ops);
		pr_info("ib_set_device_ops ok for index %d\n", i);

		// Initialize sysfs attributes
		bluerdma_init_sysfs_attrs(testing_dev[i]);

		ret = ib_register_device(ibdev, "bluerdma%d", NULL);
		if (ret) {
			pr_err("ib_register_device failed for index %d\n", i);
			while (--i >= 0) {
				ib_unregister_device(&testing_dev[i]->ibdev);
			}
			bluerdma_free_testing();
			return ret;
		}
		pr_info("ib_register_device %s\n", ibdev->name);
		
		// Create sysfs attributes
		ret = device_create_file(&ibdev->dev, &testing_dev[i]->gids_attr);
		if (ret) {
			pr_err("Failed to create gids sysfs file for device %d\n", i);
		}
		
		ret = device_create_file(&ibdev->dev, &testing_dev[i]->mac_attr);
		if (ret) {
			pr_err("Failed to create mac sysfs file for device %d\n", i);
		}
		
		if (testing_dev[i]->netdev) {
			ret = ib_device_set_netdev(ibdev,
						   testing_dev[i]->netdev, 1);
			if (ret) {
				pr_err("ib_device_set_netdev failed for index %d: %d\n",
				       i, ret);
			} else {
				pr_info("Associated netdev %s with RDMA device %s\n",
					testing_dev[i]->netdev->name,
					ibdev->name);
			}
		}
	}

	return 0;
}

static void bluerdma_ib_device_remove(struct pci_dev *pdev)
{
	// struct bluerdma_dev *dev = pci_get_drvdata(pdev);
	for (int i = 0; i < N_TESTING; i++) {
		if (testing_dev[i]) {
			// Remove sysfs attributes
			device_remove_file(&testing_dev[i]->ibdev.dev, &testing_dev[i]->gids_attr);
			device_remove_file(&testing_dev[i]->ibdev.dev, &testing_dev[i]->mac_attr);
			
			ib_unregister_device(&testing_dev[i]->ibdev);
			pr_info("ib_unregister_device ok for index %d\n", i);
		}
	}
	bluerdma_free_testing();
}

#pragma endregion ib device

#pragma region probe

static int bluerdma_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret;

	// ret = bluerdma_probe_dev(pdev);
	// pr_info("bluerdma_probe_dev ok %d\n", ret == 0);
	// if (ret)
	// 	return ret;

	ret = bluerdma_ib_device_add(pdev);
	pr_info("bluerdma_ib_device_add %d\n", ret == 0);
	if (ret) {
		// bluerdma_remove_dev(pdev);
		return ret;
	}

	return 0;
}

static void bluerdma_remove(struct pci_dev *pdev)
{
	bluerdma_ib_device_remove(pdev);
	// bluerdma_remove_dev(pdev);
}

#pragma endregion probe

#pragma region PCI Device

// static struct pci_driver bluerdma_pci_driver = {
// 	.name = DRV_MODULE_NAME,
// 	.id_table = bluerdma_pci_tbl,
// 	.probe = bluerdma_probe,
// 	.remove = bluerdma_remove
// };
// static const struct pci_device_id bluerdma_pci_tbl[] = {
// TODO: Add the correct PCI device ID
// 	{ PCI_DEVICE(PCI_VENDOR_ID_DATENLORD, 0xffff) },
// 	{}
// };
// MODULE_DEVICE_TABLE(pci, bluerdma_pci_tbl);

#pragma endregion PCI Device

#pragma region Entry Point

static int __init bluerdma_init_module(void)
{
	pr_info("DatenLord RDMA driver loaded\n");
	int ret;

	ret = request_module("ib_uverbs");
	// ret = pci_register_driver(&bluerdma_pci_driver);
	ret = bluerdma_probe(NULL, NULL);

	return 0;
}

static void __exit bluerdma_exit_module(void)
{
	pr_info("DatenLord RDMA driver unloaded\n");

	bluerdma_remove(NULL);
	// pci_unregister_driver(&bluerdma_pci_driver);
}

module_init(bluerdma_init_module);
module_exit(bluerdma_exit_module);

#pragma endregion Entry Point
