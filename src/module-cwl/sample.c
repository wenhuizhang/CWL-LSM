/*
* Sample LSM implementation
*/

//#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/kd.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/debugfs.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for sysctl_local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <asm/uaccess.h>
//#include <asm/semaphore.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <asm/uaccess.h>

// use a bit for the cwl
struct task_security_struct {
	u32 sid;
};


MODULE_LICENSE("GPL");

#define INITCONTEXTLEN 100
#define XATTR_SAMPLE_SUFFIX "sample"
#define XATTR_NAME_SAMPLE XATTR_SECURITY_PREFIX XATTR_SAMPLE_SUFFIX

#define PATHLEN 128

#define SAMPLE_IGNORE 0
#define SAMPLE_UNTRUSTED 1
#define SAMPLE_TRUSTED 2
#define SAMPLE_TARGET_SID 7

/* Mask definitions */
#define MAY_EXEC 1
#define MAY_READ 4
#define MAY_APPEND 8
#define MAY_WRITE 2
#define MAY_WRITE_EXEC 3

/* Mask definitions */
#define NOT_EXEC -1
#define NOT_READ -4
#define NOT_APPEND -8
#define NOT_WRITE -2
#define NOT_WRITE_EXEC -3

/* cwl data to bool value */
#define BOOL_CWL    !!cwl

extern struct security_operations *security_ops;
/*
* Minimal support for a secondary security module,
* just to allow the use of the capability module.
*/
//static struct security_operations *secondry_ops;


/* Convert context string to sid value (SAMPLE_*) */

static int security_context_to_sid(char *context, u32 *sid)
{
#if 0
	printk(KERN_WARNING "%s: have context: %s\n",
	       __FUNCTION__, context);
#endif

	if (!context) return -1;

	if (strcmp(context, "untrusted") == 0) {
		*sid = SAMPLE_UNTRUSTED;
#if 0
		printk(KERN_WARNING "%s: have UN-Trusted context: %s\n",
		       __FUNCTION__, context);
#endif
	}
	else if (strcmp(context, "trusted") == 0) {
		*sid = SAMPLE_TRUSTED;
#if 0
		printk(KERN_WARNING "%s: have Trusted context: %s\n",
		       __FUNCTION__, context);
#endif
	}
	else if (strcmp(context, "target") == 0)
		*sid = SAMPLE_TARGET_SID;
	else
		*sid = SAMPLE_IGNORE;

#if 0
	printk(KERN_WARNING "%s: have sid: 0x%x\n",
	       __FUNCTION__, *sid);
#endif

	return 0;
}



static int has_perm(u32 ssid_full, u32 osid, u32 ops)
{
	u32 cwl = 0xf0000000 & ssid_full;
	u32 ssid = 0xfffffff & ssid_full;
#if 0
	if (ssid && osid)
		printk(KERN_WARNING "%s: 0x%x:0x%x:0x%x:0x%x\n",
		       __FUNCTION__, ssid, cwl, osid, ops);
#endif
	/* YOUR CODE: CW-Lite Authorization Rules */
	// wenhui
	// u32 ssid = get_task_sid(task);
	// u32 osid = get_inode_sid(inode);
	// SAMPLE_IGNORE 0; SAMPLE_UNTRUSTED 1; SAMPLE_TRUSTED 2; SAMPLE_TARGET_SID 7
	//MAY_EXEC = 1; MAY_READ = 4; MAY_APPEND = 8; MAY_WRITE = 2; MAY_WRITE_EXEC = 3
	if( ssid && osid ){
		if( ssid == SAMPLE_IGNORE ) 		            						return 0;
		// if on then enforce cwlite, lower ssid to process inode
		// cwl == 0x00000000 means off, cwl == 0x10000000 means on
		// if off then enforce biba, no write/append up, no read down
		if( BOOL_CWL ){
		    if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_WRITE)) )	        return NOT_WRITE;
		    if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_APPEND)) )	        return NOT_APPEND;
		    if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_WRITE_EXEC)) )	return NOT_WRITE_EXEC;
		    return 0;
                }else{
		    if( (!(ssid^SAMPLE_TRUSTED)) && (!(osid^SAMPLE_UNTRUSTED)) && (!(ops^MAY_EXEC)) )	        return NOT_EXEC;
		    if( (!(ssid^SAMPLE_TRUSTED)) && (!(osid^SAMPLE_UNTRUSTED)) && (!(ops^MAY_READ)) )	        return NOT_READ;
		    if( (!(ssid^SAMPLE_TRUSTED)) && (!(osid^SAMPLE_UNTRUSTED)) && (!(ops^MAY_WRITE_EXEC)) )	return NOT_WRITE_EXEC;
		    if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_WRITE)) )	        return NOT_WRITE;
		    if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_APPEND)) )	        return NOT_APPEND;
		    if( (!(ssid^SAMPLE_UNTRUSTED)) && (!(osid^SAMPLE_TRUSTED)) && (!(ops^MAY_WRITE_EXEC)) )	return NOT_WRITE_EXEC;
		    return 0;
                }
		return 0;
	}
        /* Other processes - allow */
        else return 0;

	return -9;  /* should not get here */
}


static u32 inode_init_with_dentry(struct dentry *dentry, struct inode *inode)
{
	int len, rc;
	char *context;
	u32 sid;

	if (!inode->i_op->getxattr) {
		goto out;
	}

/* Need a dentry, since the xattr API requires one.
   Life would be simpler if we could just pass the inode. */

	if (!dentry) {
		printk(KERN_WARNING "%s:  no dentry for dev=%s "
		       "ino=%ld\n", __FUNCTION__, inode->i_sb->s_id,
		       inode->i_ino);
		goto out;
	}

	len = INITCONTEXTLEN;
	context = kmalloc(len, GFP_KERNEL);
	if (!context) {
		dput(dentry);
		printk(KERN_WARNING "%s: kmalloc error exit\n",
		       __FUNCTION__);
		goto out;
	}
	rc = inode->i_op->getxattr(dentry, XATTR_NAME_SAMPLE,
				   context, len);
	len = rc;
	if (rc == -ERANGE) {
		/* Need a larger buffer.  Query for the right size. */
		rc = inode->i_op->getxattr(dentry, XATTR_NAME_SAMPLE,
					   NULL, 0);
		if (rc < 0) {
			dput(dentry);
			kfree(context);
			goto out;
		}
		kfree(context);
		len = rc;
		context = kmalloc(len, GFP_KERNEL);
		if (!context) {
			rc = -ENOMEM;
			dput(dentry);
			printk(KERN_WARNING "%s: no mem error exit\n",
			       __FUNCTION__);
			goto out;
		}
		rc = inode->i_op->getxattr(dentry,
					   XATTR_NAME_SAMPLE,
					   context, len);
	}
	dput(dentry);
	if (rc < 0) {
		kfree(context);
		goto out;
	} else {
		/* not always null terminated at length */
		context[len] = '\0';
		/* We have a legit context */
		rc = security_context_to_sid(context, &sid);
#if 0
		printk(KERN_WARNING "%s:  context_to_sid(%s:%d) "
		       "returned 0x%x for dev=%s ino=%ld\n",
		       __FUNCTION__, context, len, sid,
		       inode->i_sb->s_id, inode->i_ino);
#endif
		if (rc) {
#if 0
			printk(KERN_WARNING "%s:  context_to_sid(%s) "
			       "returned %d for dev=%s ino=%ld\n",
			       __FUNCTION__, context, -rc,
			       inode->i_sb->s_id, inode->i_ino);
#endif
			/* Leave with the unlabeled SID */
			sid = SAMPLE_IGNORE;
		}
	}
	kfree(context);
	return sid;

out:
	return SAMPLE_IGNORE;
}


static u32 get_task_sid(struct task_struct *task)
{
	return (u32) task->security;
}


static u32 get_inode_sid(struct inode *inode)
{
	struct dentry *dentry;

	dentry = d_find_alias(inode);
	return inode_init_with_dentry(dentry, inode);
}


static int inode_has_perm(struct task_struct *task,
		  struct inode *inode, int ops,
		  struct vfsmount *mnt, struct dentry *dentry)
{
	//wenhui
	if (inode == NULL) return 0;

	u32 ssid = get_task_sid(task);
	u32 osid = get_inode_sid(inode);
	int rtn = 0;
	char *pname = (char *)NULL, *buf;
	int len = PATHLEN;

/* get pathname for exceptions and printing */
	buf = kmalloc(len, GFP_KERNEL);

	if (buf && dentry && mnt) {  // && nd->dentry && nd->mnt
		buf = memset(buf, '\0', len);
		pname = d_path(dentry, mnt, buf, len-1);
#if 0
		if (ssid && osid) {
			printk(KERN_WARNING "%s: path: 0x%x with val %s; buf 0x%x with val %s\n",
			       __FUNCTION__, pname, pname, buf, buf);
		}
#endif
	}

/* exceptions */
	if (pname && (len >= 4)) {
		if (!strncmp(buf, "/dev", 4))  // allow /dev
			goto done;
		if (!strncmp(buf, "/proc", 5)) // allow /proc
			goto done;
		if (!strncmp(buf, "/var", 4)) // allow /var - no xattr
			goto done;
	}

/* YOUR CODE: do authorize */
	//wenhui
	//static int has_perm(u32 ssid_full, u32 osid, u32 ops)
	rtn = has_perm(ssid, osid, ops);

/* Then, use this code to print relevant denials: for our processes or on our objects */
	if (( ssid && osid ) && rtn ) {
		printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x "
		       "NOT authorized (%d) for inode osid 0x%x (file:%s) for ops 0x%x\n",
		       __FUNCTION__, current->pid, ssid, rtn, osid,
		       (pname ? pname : "unk?"), ops);
}

/* Then, use this code to print relevant authorizations: for our processes */
	if (( ssid && osid ) &&
	    ( !rtn )) {
		printk(KERN_WARNING "%s: target task pid=%d of ssid 0x%x "
		       "authorized for inode osid:ops 0x%x:0x%x (file:%s) \n",
		       __FUNCTION__, current->pid, ssid, osid, ops,
		       (pname ? pname : "unk?"));
	}

done:
	kfree(buf);
	return rtn;
}


static int sample_inode_permission(struct inode *inode, int mask,
			   struct nameidata *nd)
{
	struct vfsmount *mnt = (struct vfsmount *)NULL;
	struct dentry *dentry = (struct dentry *)NULL;
	int rtn;

/* no need to check if no mask (ops) */
	if (!mask) {
		/* No permission to check.  Existence test. */
		return 0;
	}

	/* get the dentry for inode_has_perm */
	if ( nd ) {
		mnt = nd->mnt;
		dentry = nd->dentry;
	}

#if 0
	if ( current->security ) {  // ssid
		printk(KERN_WARNING "%s: file path info: mnt: 0x%x; dentry 0x%x\n",
		       __FUNCTION__, mnt, dentry);
	}
#endif

	rtn = inode_has_perm(current, inode, mask, mnt, dentry);

	return 0; /* permissive */
}



/* Label process based on xattr of executable file */

static int sample_bprm_set_security(struct linux_binprm *bprm)
{
	struct inode *inode = bprm->file->f_dentry->d_inode;
	/* YOUR CODE: Determine the label for the new process */
	//wenhui
  	u32 osid = get_inode_sid(inode);

/* if the inode's sid indicates trusted or untrusted, then set
   task->security */
	if (osid) {
		current->security = (void *)osid;
		printk(KERN_WARNING "%s: set task pid=%d of ssid 0x%x\n",
		       __FUNCTION__, current->pid, osid);
	}

	return 0;
}


static int sample_inode_init_security(struct inode *inode, struct inode *dir,
			       char **name, void **value,
			       size_t *len)
{
	u32 ssid = get_task_sid(current);
	u32 actual_ssid = 0xfffffff & ssid;
	char *namep = NULL;
	char *valuep = NULL;

	if (!inode || !dir)
		return -EOPNOTSUPP;

	if (actual_ssid == SAMPLE_IGNORE)
		return -EOPNOTSUPP;

	printk(KERN_WARNING "%s: pid %d:0x%x creating a new file\n",
	       __FUNCTION__, current->pid, ssid);

/* get attribute name */
	namep = kstrdup(XATTR_SAMPLE_SUFFIX, GFP_KERNEL);
	if (!namep)
		return -ENOMEM;
	*name = namep;

/* set xattr value and length */
	if (actual_ssid == SAMPLE_TRUSTED) {
		valuep = kstrdup("trusted", GFP_KERNEL);
		*len = 8;
		printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x creates Trusted object\n",
		       __FUNCTION__, current->pid, actual_ssid);
	}
	else if (actual_ssid == SAMPLE_UNTRUSTED) {
		valuep = kstrdup("untrusted", GFP_KERNEL);
		*len = 10;
		printk(KERN_WARNING "%s: task pid=%d of ssid 0x%x creates UN-Trusted object\n",
		       __FUNCTION__, current->pid, actual_ssid);
	}

	if (!valuep)
		return -ENOMEM;
	*value = valuep;

	return 0;
}


int sample_inode_setxattr (struct dentry *dentry, char *name, void *value,
				      size_t size, int flags)
{
	struct inode *inode;
	u32 mask = MAY_WRITE;
	struct vfsmount *mnt = (struct vfsmount *)NULL;
	u32 ssid, osid;
	int rtn;

	if (!strncmp(name, XATTR_NAME_SAMPLE,
		     sizeof(XATTR_NAME_SAMPLE) - 1)) {
		// sample ignores these
		return 0;
	}

	if (!dentry || !dentry->d_inode) {
		return -EPERM;
	}

	/* YOUR CODE: Gather inputs for inode_has_perm */
	//wenhui
        // current is a global current pointer
	inode = dentry->d_inode;
	ssid = get_task_sid(current);
	osid = get_inode_sid(inode);


/* record attribute setting request before authorization */
	if (ssid && osid) {
		printk(KERN_WARNING "%s: task pid=%d of label 0x%x setting attribute %s"
		       "for object of label 0x%x\n",
		       __FUNCTION__, current->pid, ssid, (name ? name : "unk?"), osid);
	}

	rtn = inode_has_perm(current, inode, mask, mnt, dentry);

	return 0;
}


int sample_inode_create (struct inode *inode, struct dentry *dentry,
                               int mask)
{
	u32 ssid = get_task_sid(current);
	u32 osid;

	if (!inode) {
		printk(KERN_WARNING "%s: no inode created by task of ssid 0x%x\n",
		       __FUNCTION__, ssid);
		return 0;
	}

	osid = get_inode_sid(inode);

	if (ssid == SAMPLE_UNTRUSTED) {
		printk(KERN_WARNING "%s: untrusted task pid=%d with sid 0x%x"
			" creating file %s of sid 0x%x\n",
		       __FUNCTION__, current->pid, ssid, "filename", osid);
	}

        return 0;
}


int sample_file_permission (struct file *file, int mask)
{
        struct inode *inode;
	struct vfsmount *mnt = (struct vfsmount *)NULL;
	struct dentry *dentry = (struct dentry *)NULL;
	int rtn;

	/* no need to check if no mask (ops) */
        if (!mask) {
                /* No permission to check.  Existence test. */
		return 0;
        }

	/* NULL file */
	if (!file || !file->f_path.dentry) {
		printk(KERN_WARNING "%s: no file by task of pid 0x%x\n",
		       __FUNCTION__, current->pid);
		return 0;
	}

	/* YOUR CODE: Collect arguments for call to inode_has_perm */
	//wenhui
        // current is a global current pointer
	//inode = file->f_dentry->d_inode;
	inode = file->f_path.dentry->d_inode;
        dentry = file->f_path.dentry;
	mnt = file->f_path.mnt;


	if ( current->security ) {  // ssid
#if 0
		printk(KERN_WARNING "%s: file path info: mnt: 0x%x; dentry 0x%x\n",
		       __FUNCTION__, mnt, dentry);
#endif
	}

	rtn = inode_has_perm(current, inode, mask, mnt, dentry);

	return 0; /* permissive */
}


static struct security_operations sample_ops = {
	.inode_permission =		sample_inode_permission,
	.bprm_set_security =		sample_bprm_set_security,
	.inode_init_security =		sample_inode_init_security,
	.inode_setxattr =		sample_inode_setxattr,
	.inode_create =			sample_inode_create,
	.file_permission =		sample_file_permission,
};

static struct dentry *cwl_debugfs_root;
static struct dentry *d_cwl;
static struct dentry *d_cwlite;


static size_t cwlite_read(struct file *filp, char __user *buffer,
				size_t count, loff_t *ppos)
{
	/* YOUR CODE: for reading the CW-Lite value from the kernel */
	//wenhui
	char tmpbuf[1];
	u32 ssid = get_task_sid(current);
	u32 cwl = 0xf0000000 & ssid;

	if(cwl == 0){
		*tmpbuf = '0';
	}else{
		*tmpbuf = '1';
	}


	if( *ppos >= 1 )					return 0;
	if( *ppos + count > 1 ) 				count = 1 - *ppos;
	if(copy_to_user(buffer, tmpbuf + *ppos, count))		return -EFAULT;

	*ppos += count;

	return count;
}


static ssize_t cwlite_write(struct file *filp, const char __user *buffer,
                                 size_t count, loff_t *ppos)
{
        int new_value;

	/* YOUR CODE: for collecting value to write from user space */
	//wenhui
	char page[1];

	if( *ppos >= 1 )						return 0;
	if( *ppos + count > 1 )					count = 1 - *ppos;
	if(copy_from_user(page + *ppos, buffer, count))		return -EFAULT;

	*ppos += count;

	if(*page == '0'){
		new_value = 0;
	}else{
		new_value = 1;
	}

        // get current
	// set flag on task
        switch (new_value) {
        case 0:
                current->security = (void *)(0xfffffff & (u32)current->security);
                printk(KERN_INFO "sample: New security setting (0): pid=%d, sec=0x%x\n",
				current->pid, (unsigned int) current->security);
                break;
        case 1:
                current->security = (void *)(0x10000000 | (u32)current->security);
                printk(KERN_INFO "sample: New security setting (1): pid=%d, sec=0x%x\n",
				current->pid, (unsigned int) current->security);
                break;
        default:
                printk(KERN_INFO "%s: invalid CW-Lite value %d\n",
                        __FUNCTION__, new_value);
		return -EINVAL;
		break;
        }

out:
	return count;
}


static struct file_operations cwlite_ops = {
	.owner = THIS_MODULE,
	.read = cwlite_read,
	.write = cwlite_write,
};


static __init int sample_init(void)
{
        if (register_security (&sample_ops)) {
                printk(KERN_INFO "Sample: Unable to register with kernel.\n");
                return 0;
        }

        printk(KERN_INFO "Sample:  Initializing.\n");
	//wenhui
	//creates dir of cwl in /sys/kernel/debugfs *
	cwl_debugfs_root = debugfs_create_dir("cwl", NULL);
        if ( !cwl_debugfs_root ) {
        	printk(KERN_INFO "Sample: Creating debugfs 'cwl' dir failed\n");
		return -ENOENT;
	}

	/* YOUR CODE: Create debugfs file "cwlite" under "cwl" directory */
	//wenhui
	//static struct dentry *d_cwl;
	//static struct dentry *d_cwlite;
	// 0666 perms read and write file operations
	d_cwlite = debugfs_create_file("cwlite", 0666, cwl_debugfs_root, NULL, &cwlite_ops);
	if( !d_cwlite ) {
        	printk(KERN_INFO "Sample: Creating debugfs 'cwlite' file failed\n");
		goto Fail;
	}
	//wenhui
        //printk(KERN_INFO "Sample:  Debugfs created: cwl: 0x%x, cwlite: 0x%x.\n",
	//	cwl_debugfs_root, d_cwl);
        printk(KERN_INFO "Sample:  Debugfs created: cwl: 0x%pd, cwlite: 0x%pd.\n",
		cwl_debugfs_root, d_cwlite);

        return 0;

Fail:
        debugfs_remove(cwl_debugfs_root);
        cwl_debugfs_root = NULL;
        return -ENOENT;
}


static __exit void sample_exit(void)
{
        printk(KERN_INFO "Sample: Exiting.\n");

	debugfs_remove(d_cwlite);
	debugfs_remove(cwl_debugfs_root);
        unregister_security(&sample_ops);
}



module_init(sample_init);
module_exit(sample_exit);


MODULE_LICENSE("GPL");
EXPORT_SYMBOL_GPL(sample_init);
EXPORT_SYMBOL_GPL(sample_exit);
