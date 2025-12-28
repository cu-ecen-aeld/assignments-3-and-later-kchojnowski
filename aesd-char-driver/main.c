/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Your Name Here"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t i, offset, written = 0;
    struct aesd_buffer_entry* entry = NULL;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    mutex_lock(&aesd_device.lock);

    for(i = *f_pos; i < count + *f_pos; i++) {
        offset = 0;
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(
                    &aesd_device.buffer, i, &offset);
	if(entry == NULL)
            break;
        copy_to_user(buf + written, &entry->buffptr[offset], 1);
	written++;
    }
    *f_pos += written;
    mutex_unlock(&aesd_device.lock);
    return written;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_buffer_entry entry;
    void* retptr = NULL;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    mutex_lock(&aesd_device.lock);

    if(aesd_device.tmpbuf == NULL) {
        aesd_device.tmpbuf = kmalloc(count, GFP_KERNEL);
        copy_from_user(aesd_device.tmpbuf, buf, count);
        aesd_device.tmpbuflen = count;
    } else {
        char* newtmpbuf = kmalloc(count + aesd_device.tmpbuflen, GFP_KERNEL);
	memcpy(newtmpbuf, aesd_device.tmpbuf, aesd_device.tmpbuflen);
        copy_from_user(newtmpbuf + aesd_device.tmpbuflen, buf, count);
	kfree(aesd_device.tmpbuf);
        aesd_device.tmpbuf = newtmpbuf;
        aesd_device.tmpbuflen += count;	
    }

    if(aesd_device.tmpbuf[aesd_device.tmpbuflen - 1] == '\n') {
        entry.size = aesd_device.tmpbuflen;
        entry.buffptr = aesd_device.tmpbuf;
	aesd_device.tmpbuflen = 0;
	aesd_device.tmpbuf = NULL;
        retptr = aesd_circular_buffer_add_entry(&aesd_device.buffer, &entry);
        if(retptr != NULL)
            kfree(retptr);
    }
    *f_pos += count;
    mutex_unlock(&aesd_device.lock);
    return count;
}

loff_t aesd_llseek(struct file *file, loff_t offset, int whence)
{
    struct aesd_buffer_entry *entry;
    size_t index, size = 0;
    loff_t retval = 0;

    PDEBUG("llseek %lld whence %d", offset, whence);
    
    mutex_lock(&aesd_device.lock);
    
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
        size += entry->size;
    }

    retval = fixed_size_llseek(file, offset, whence, size);
    
    mutex_unlock(&aesd_device.lock);
    return retval;
}

static long aesd_adjust_file_offset(
		struct file *file, uint32_t write_cmd, uint32_t write_cmd_offset)
{
    mutex_lock(&aesd_device.lock);
    if((aesd_device.buffer.in_offs == aesd_device.buffer.out_offs) 
        && (!aesd_device.buffer.full))
        return -EINVAL;
    if(write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        return -EINVAL;
    uint8_t cmd = aesd_device.buffer.out_offs;
    uint8_t i = 0;
    loff_t fpos = 0;
    for(i = 0; i < write_cmd; i++) {
        if(aesd_device.buffer.entry[cmd].size == 0)
            return -EINVAL;
        fpos += aesd_device.buffer.entry[cmd].size;
	cmd++;
	if(cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
	    cmd = 0;
    }

    if((aesd_device.buffer.entry[cmd].size == 0)
       || (write_cmd_offset >= aesd_device.buffer.entry[cmd].size))
        return -EINVAL;
    fpos += write_cmd_offset;
    file->f_pos = fpos;
    mutex_unlock(&aesd_device.lock);
    return 0;
}

long aesd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct aesd_seekto seekto;
    if(cmd == AESDCHAR_IOCSEEKTO) {
	copy_from_user(&seekto, (const void __user *)arg, sizeof(struct aesd_seekto));
        PDEBUG("ioctl IOCSEEKTO %u %u", seekto.write_cmd, seekto.write_cmd_offset);
	return aesd_adjust_file_offset(file, seekto.write_cmd, seekto.write_cmd_offset);
    }
    return 0;
}

struct file_operations aesd_fops = {
    .owner =          THIS_MODULE,
    .read =           aesd_read,
    .write =          aesd_write,
    .open =           aesd_open,
    .release =        aesd_release,
    .llseek =         aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    PDEBUG("init module");
    aesd_circular_buffer_init(&aesd_device.buffer);
    aesd_device.tmpbuf = NULL;
    aesd_device.tmpbuflen = 0;
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    struct aesd_buffer_entry *entry;
    size_t index;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    PDEBUG("cleanup module");
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
      kfree(entry->buffptr);
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
