import concurrent.futures
import json
import random
import string
import traceback

from looseversion import LooseVersion

from ceph.parallel import parallel
from tests.cephfs.cephfs_utilsV1 import FsUtils
from tests.cephfs.lib.cephfs_refinode_utils import RefInodeUtils
from utility.log import Log
from utility.utils import get_ceph_version_from_cluster

log = Log(__name__)


def get_clone_status(client, fs_util, clone):
    cmd_out, cmd_rc = fs_util.get_clone_status(
        client, clone["vol_name"], clone["target_subvol_name"]
    )
    status = json.loads(cmd_out)
    log.info(f"{clone['target_subvol_name']} status is {status['status']['state']}")
    return status["status"]["state"]


def run(ceph_cluster, **kw):
    """
    Pre-requisites :
    1. We need atleast one client node to execute this test case
    1. creats fs volume create cephfs if the volume is not there
    2. ceph fs subvolumegroup create <vol_name> <group_name> --pool_layout <data_pool_name>
        Ex : ceph fs subvolumegroup create cephfs subvolgroup_1
    3. ceph fs subvolume create <vol_name> <subvol_name> [--size <size_in_bytes>] [--group_name <subvol_group_name>]
       [--pool_layout <data_pool_name>] [--uid <uid>] [--gid <gid>] [--mode <octal_mode>]  [--namespace-isolated]
       Ex: ceph fs subvolume create cephfs subvol_2 --size 5368706371 --group_name subvolgroup_
    4. Create Data on the subvolume
        Ex:  python3 /home/cephuser/smallfile/smallfile_cli.py --operation create --threads 10 --file-size 400 --files
            100 --files-per-dir 10 --dirs-per-dir 2 --top /mnt/cephfs_fuse1baxgbpaia_1/
    5. Create snapshot of the subvolume
        Ex: ceph fs subvolume snapshot create cephfs subvol_2 snap_1 --group_name subvolgroup_1

    Concurrent Clone Operations:
    1. Validate default value foe the clones i.e., 4
    2. Create 5 clones of the snap_1
        Ex: ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_1 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_2 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_3 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_4 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_5 --group_name subvolgroup_1
    3. Get the status of each clone using below command
        Ex: ceph fs clone status cephfs clone_1
            ceph fs clone status cephfs clone_2
            ceph fs clone status cephfs clone_3
            ceph fs clone status cephfs clone_4
            ceph fs clone status cephfs clone_5
    4. We are validating the total clones in_progress should not be greater than 4
    5. Once all the clones moved to complete state we are deleting all the clones
    6. Set the concurrent threads to 2
        Ex: ceph config set mgr mgr/volumes/max_concurrent_clones 2
    7. Create 5 clones of the snap_1
        Ex: ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_1 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_2 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_3 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_4 --group_name subvolgroup_1
            ceph fs subvolume snapshot clone cephfs subvol_2 snap_1 clone_5 --group_name subvolgroup_1
    8. Get the status of each clone using below command
        Ex: ceph fs clone status cephfs clone_1
            ceph fs clone status cephfs clone_2
            ceph fs clone status cephfs clone_3
            ceph fs clone status cephfs clone_4
            ceph fs clone status cephfs clone_5
    9. We are validating the total clones in_progress should not be greater than 2
    10.Once all the clones moved to complete state we are deleting all the clones
    Clean-up:
    1. ceph fs snapshot rm <vol_name> <subvol_name> snap_name [--group_name <subvol_group_name>]
    2. ceph fs subvolume rm <vol_name> <subvol_name> [--group_name <subvol_group_name>]
    3. ceph fs subvolumegroup rm <vol_name> <group_name>
    """
    try:
        test_data = kw.get("test_data")
        fs_util = FsUtils(ceph_cluster, test_data=test_data)
        erasure = (
            FsUtils.get_custom_config_value(test_data, "erasure")
            if test_data
            else False
        )
        config = kw.get("config")
        clients = ceph_cluster.get_ceph_objects("client")
        build = config.get("build", config.get("rhbuild"))
        fs_util.prepare_clients(clients, build)
        fs_util.auth_list(clients)
        ref_inode_utils = RefInodeUtils(ceph_cluster)
        ceph_version = get_ceph_version_from_cluster(clients[0])
        log.info("checking Pre-requisites")
        if len(clients) < 1:
            log.info(
                f"This test requires minimum 1 client nodes.This has only {len(clients)} clients"
            )
            return 1
        log.info("setting 'snapshot_clone_no_wait' to false")
        clients[0].exec_command(
            sudo=True,
            cmd="ceph config set mgr mgr/volumes/snapshot_clone_no_wait false",
        )
        default_fs = "cephfs" if not erasure else "cephfs-ec"
        mounting_dir = "".join(
            random.choice(string.ascii_lowercase + string.digits)
            for _ in list(range(10))
        )
        client1 = clients[0]
        fs_details = fs_util.get_fs_info(client1, default_fs)
        rmclone_list = [
            {"vol_name": default_fs, "subvol_name": f"clone_{x}"} for x in range(1, 6)
        ]
        if not fs_details:
            fs_util.create_fs(client1, default_fs)
        subvolumegroup = {"vol_name": default_fs, "group_name": "subvolgroup_1"}
        fs_util.create_subvolumegroup(client1, **subvolumegroup)
        subvolume = {
            "vol_name": default_fs,
            "subvol_name": "subvol_2",
            "group_name": "subvolgroup_1",
            "size": "5368706371",
        }
        fs_util.create_subvolume(client1, **subvolume)
        log.info("Get the path of sub volume")
        subvol_path, rc = client1.exec_command(
            sudo=True,
            cmd=f"ceph fs subvolume getpath {default_fs} subvol_2 subvolgroup_1",
        )
        fuse_mounting_dir_1 = f"/mnt/cephfs_fuse{mounting_dir}_1/"
        fs_util.fuse_mount(
            [client1],
            fuse_mounting_dir_1,
            extra_params=f" -r {subvol_path.strip()} --client_fs {default_fs}",
        )

        if LooseVersion(ceph_version) >= LooseVersion("20.1"):
            ref_inode_utils.allow_referent_inode_feature_enablement(
                client1, default_fs, enable=True
            )
            log.info("Ceph version >= 20.1 detected. Creating referent inode setup.")
            ref_base_path = fuse_mounting_dir_1
            ref_inode_utils.create_directories(
                client1, ref_base_path, ["dirA", "dirA/dirB"]
            )
            ref_inode_utils.create_file_with_content(
                client1, "%s/dirA/fileA1" % ref_base_path, "data in file A1"
            )
            ref_inode_utils.create_file_with_content(
                client1, "%s/dirA/dirB/fileB1" % ref_base_path, "data in file B1"
            )
            main_file = "%s/file1" % ref_base_path
            ref_inode_utils.create_file_with_content(
                client1, main_file, "original file content"
            )
            hardlinks = [
                "%s/file1_hardlink1" % ref_base_path,
                "%s/file1_hardlink2" % ref_base_path,
                "%s/dirA/file1_hardlink_in_dirA" % ref_base_path,
            ]
            for hl in hardlinks:
                ref_inode_utils.create_hardlink_and_validate(
                    client1,
                    fs_util,
                    main_file,
                    hl,
                    "cephfs.%s.data" % default_fs,
                    default_fs,
                )

        client1.exec_command(
            sudo=True,
            cmd=f"python3 /home/cephuser/smallfile/smallfile_cli.py --operation create --threads 10 --file-size 4000 "
            f"--files 100 --files-per-dir 10 --dirs-per-dir 2 --top "
            f"{fuse_mounting_dir_1}",
            timeout=3600,
        )
        snapshot = {
            "vol_name": default_fs,
            "subvol_name": "subvol_2",
            "snap_name": "snap_1",
            "group_name": "subvolgroup_1",
        }
        fs_util.create_snapshot(client1, **snapshot)
        clone_list = [
            {
                "vol_name": default_fs,
                "subvol_name": "subvol_2",
                "snap_name": "snap_1",
                "target_subvol_name": f"clone_{x}",
                "group_name": "subvolgroup_1",
            }
            for x in range(1, 6)
        ]
        with parallel() as p:
            for clone in clone_list:
                p.spawn(fs_util.create_clone, client1, **clone, validate=False)
        status_list = []
        iteration = 0
        while status_list.count("complete") < len(clone_list):
            status_list.clear()
            iteration += 1
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(get_clone_status, client1, fs_util, clone)
                    for clone in clone_list
                ]
            status_list = [f.result() for f in futures]
            print(status_list)
            if status_list.count("in-progress") > 4:
                return 1
            else:
                log.info(
                    f"cloneing is in progress for {status_list.count('in-progress')} out of {len(clone_list)}"
                )
            log.info(f"Iteration {iteration} has been completed")

        rmclone_list = [
            {"vol_name": default_fs, "subvol_name": f"clone_{x}"} for x in range(1, 6)
        ]
        rmclone_cancel_list = [
            {"vol_name": default_fs, "clone_name": f"clone_{x}"} for x in range(1, 6)
        ]
        for clonevolume in rmclone_list:
            fs_util.remove_subvolume(client1, **clonevolume)
        log.info("Set clone threads to 2 and verify only 2 clones are in progress")
        client1.exec_command(
            sudo=True, cmd="ceph config set mgr mgr/volumes/max_concurrent_clones 2"
        )
        with parallel() as p:
            for clone in clone_list:
                p.spawn(fs_util.create_clone, client1, **clone, validate=False)
        status_list = []
        iteration = 0
        while status_list.count("complete") < len(clone_list):
            iteration += 1
            status_list.clear()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(get_clone_status, client1, fs_util, clone)
                    for clone in clone_list
                ]
            status_list = [f.result() for f in futures]
            print(status_list)
            if status_list.count("in-progress") > 2:
                return 1
            else:
                log.info(
                    f"cloning is in progress for {status_list.count('in-progress')} out of {len(clone_list)}"
                )
            log.info(f"Iteration {iteration} has been completed")

        if LooseVersion(ceph_version) >= LooseVersion("20.1"):
            ref_inode_utils.allow_referent_inode_feature_enablement(
                client1, default_fs, enable=False
            )

        return 0
    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        return 1

    finally:
        log.info("Setting back the clones to default value 4")
        client1.exec_command(
            sudo=True, cmd="ceph config set mgr mgr/volumes/max_concurrent_clones 4"
        )
        log.info("setting 'snapshot_clone_no_wait' to true")
        clients[0].exec_command(
            sudo=True, cmd="ceph config set mgr mgr/volumes/snapshot_clone_no_wait true"
        )
        if locals().get("rmclone_cancel_list", None):
            for clonevolume in rmclone_cancel_list:
                fs_util.clone_cancel(
                    client1, **clonevolume, force=True, validate=False, check_ec=False
                )

        if locals().get("rmclone_list", None):
            for clonevolume in rmclone_list:
                fs_util.remove_subvolume(
                    client1, **clonevolume, force=True, validate=False, check_ec=False
                )
        log.info("Clean Up in progess")
        fs_util.remove_snapshot(client1, **snapshot, validate=False, check_ec=False)
        fs_util.remove_subvolume(client1, **subvolume, validate=False, check_ec=False)
