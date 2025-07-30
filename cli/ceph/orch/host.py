from cli import Cli
from cli.utilities.utils import build_cmd_from_args


class Host(Cli):
    def __init__(self, nodes, base_cmd):
        super(Host, self).__init__(nodes)
        self.base_cmd = f"{base_cmd} host"

    def ls(self, **kw):
        """
        List hosts
        Args:
            kw (dict): Key/value pairs that needs to be provided to the installer

            Supported Keys:
                format (str): the type to be formatted(yaml)
                host_pattern (str) : host name
                label (str) : label
                host_status (str) : host status
        """
        cmd = f"{self.base_cmd} ls {build_cmd_from_args(**kw)}"
        out = self.execute(sudo=True, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def maintenance(self, hostname, operation, force=False, yes_i_really_mean_it=False):
        """
        Add/Remove the specified host from maintenance mode
        Args:
            hostname(str): name of the host which needs to be added into maintenance mode
            operation(str): enter/exit maintenance mode
            force (bool): Whether to append force with maintenance enter command
            yes-i-really-mean-it (bool) : Whether to append --yes-i-really-mean-it with maintenance enter command
        """
        cmd = f"{self.base_cmd} maintenance {operation} {hostname}"
        if force:
            cmd += " --force"
        if yes_i_really_mean_it:
            cmd += " --yes-i-really-mean-it"
        out = self.execute(cmd=cmd, sudo=True)
        if not out:
            return False
        return True

    def add(self, hostname, ip_address, label=None):
        """
        Use the cephadm orchestrator to add hosts to the storage cluster:
        Args:
            hostname (str): Hostname of the node to be added
            ip_address (str): Ip address of the node to be added
            label (str): Label to be added to the node
        """
        cmd = f"{self.base_cmd} add {hostname} {ip_address}"
        if label:
            cmd += f" {label}"
        out = self.execute(cmd=cmd, sudo=True)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def drain(self, host, force=False, zap_osd_devices=False):
        """
        Drains a given host
        Args:
            host (ceph): Ceph host to be drained
            force (bool): whether to force the operation or not
            zap_osd_devices (bool): To zap the osd devices
        """
        cmd = f"{self.base_cmd} drain {host}"
        if force:
            cmd += " --force"
        if zap_osd_devices:
            cmd += " --zap-osd-devices"
        out = self.execute(cmd=cmd, sudo=True)
        if isinstance(out, tuple):
            return out[0].strip()
        return out

    def set_topological_labels(self, hostname, label=None):
        """
        Add/Remove topological label used for staggered upgrade
        Args:
          hostname (str): host name
          label (str): label name
        Note: If no label is passed, command removes existing
        topological labels for that host
        """
        cmd = f"{self.base_cmd} set-topological-labels {hostname} {label}"
        out = self.execute(sudo=True, cmd=cmd)
        if isinstance(out, tuple):
            return out[0].strip()
        return out
