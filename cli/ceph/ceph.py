from cli import Cli

from .auth.auth import Auth
from .balancer import Balancer
from .config import Config
from .config_key import ConfigKey
from .crash import Crash
from .fs.fs import Fs
from .mgr.mgr import Mgr
from .nfs.nfs import Nfs
from .orch.orch import Orch
from .osd.osd import Osd
from .restful.restful import RestFul
from .rgw.rgw import Rgw
from .smb.smb import Smb


class Ceph(Cli):
    """This module provides CLI interface for deployment and maintenance of ceph cluster."""

    def __init__(self, nodes, base_cmd=""):
        super(Ceph, self).__init__(nodes)

        self.base_cmd = f"{base_cmd} ceph" if base_cmd else "ceph"
        self.auth = Auth(nodes, self.base_cmd)
        self.mgr = Mgr(nodes, self.base_cmd)
        self.orch = Orch(nodes, self.base_cmd)
        self.rgw = Rgw(nodes, self.base_cmd)
        self.balancer = Balancer(nodes, self.base_cmd)
        self.config_key = ConfigKey(nodes, self.base_cmd)
        self.config = Config(nodes, self.base_cmd)
        self.crash = Crash(nodes, self.base_cmd)
        self.nfs = Nfs(nodes, self.base_cmd)
        self.fs = Fs(nodes, self.base_cmd)
        self.osd = Osd(nodes, self.base_cmd)
        self.smb = Smb(nodes, self.base_cmd)
        self.restful = RestFul(nodes, self.base_cmd)

    def version(self):
        """Get ceph version."""
        cmd = f"{self.base_cmd} version"
        out = self.execute(sudo=True, check_ec=False, long_running=False, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def status(self):
        """Get ceph status."""
        cmd = f"{self.base_cmd} status"
        out = self.execute(sudo=True, check_ec=False, long_running=False, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def fsid(self):
        """Get ceph cluster FSID."""
        cmd = f"{self.base_cmd} fsid"
        out = self.execute(sudo=True, check_ec=False, long_running=False, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def insights(self, prune=False, hours=None):
        """
        Performs ceph insights related operations
        Args:
            prune (bool): To delete the existing insights reports
            hours (str): Delete logs from given hours, 0 to delete all
        """
        cmd = f"{self.base_cmd} insights"
        if prune:
            # Remove historical health data older than <hours>.
            # Passing 0 for <hours> will clear all health data.
            cmd += f"prune-health {hours}"
        out = self.execute(sudo=True, check_ec=False, long_running=False, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def health(self, detail=False):
        """Returns the Ceph cluster health"""
        cmd = f"{self.base_cmd} health"
        if detail:
            cmd += " detail"
        out = self.execute(sudo=True, check_ec=False, long_running=False, cmd=cmd)
        if isinstance(out, dict):
            for key, value in out.items():
                if isinstance(value, tuple):
                    return value[0].strip()
                else:
                    return value[0]
        elif isinstance(out, tuple):
            return out[0].strip()
        return out

    def dashboard(self, **kw):
        """
        Executed ceph dashboard commands
        Args:
            kw (dict): Key/value pairs of dashboard command arg
            Supported Keys:
                set-jwt-token-ttl <seconds:int>
                dashboard create-self-signed-cert
                grafana dashboards update
                get-account-lockout-attempts
                set-account-lockout-attempts <value>
                reset-account-lockout-attempts
                get-alertmanager-api-host
                set-alertmanager-api-host <value>
                reset-alertmanager-api-host
        """
        cmd = f"{self.base_cmd} dashboard "
        for key, val in kw.items():
            cmd += f"{key} {val}"
        out = self.execute(sudo=True, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def logs(self, num, channel, level=None):
        """
        Run the ceph logs command to get the
        cephadm logs
        Args:
            num(str): Number of logs required
            level(str): Log level debug|info|sec|warn|error
            channel(str): Get logs for channel cluster|audit|cephadm
        """
        cmd = f"{self.base_cmd} log last"
        if level:
            cmd += f" {level}"
        cmd += f" {channel}"
        out = self.execute(sudo=True, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out
