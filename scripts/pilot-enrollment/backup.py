"""One stopped-writer encrypted authority backup and read-only restore check.

Ubuntu pilot host only. The reviewed caller stops services and preserves its new
serving/deployment inputs first. This hook never starts services, formats media,
changes keyslots, overwrites backups or automatically retries a partial attempt.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r
import recovery

IMAGE = Path('/var/lib/kaiba-pilot/authority.luks')
SOURCE = Path('/srv/kaiba-pilot')
MAPPER = Path('/dev/mapper/kaiba-pilot-authority')
SERVICES = tuple('kaiba-pilot-'+name+'.service' for name in
                 ('serving', 'fleet', 'issuer', 'observation', 'admission', 'postgres'))
SIZE = 2*1024*1024*1024


def file_hash(path):
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    h = hashlib.sha256()
    with os.fdopen(fd, 'rb') as stream:
        r.require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'backup-special-file')
        for chunk in iter(lambda: stream.read(4*1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def copy_exclusive(source, destination, size):
    source_fd = os.open(source, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info = os.fstat(source_fd)
        r.require(stat.S_ISREG(info.st_mode) and info.st_size == size, 'backup-source-size')
        output_fd = os.open(destination, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        h = hashlib.sha256()
        with os.fdopen(output_fd, 'wb') as output:
            left = size
            while left:
                data = os.read(source_fd, min(left, 4*1024*1024))
                r.require(bool(data), 'backup-source-short')
                output.write(data); h.update(data); left -= len(data)
            r.require(not os.read(source_fd, 1), 'backup-source-grew')
            output.flush(); os.fsync(output.fileno())
        return h.hexdigest()
    finally:
        os.close(source_fd)


def snapshot(root):
    """Private comparison in memory only; never emit names/content/key values."""
    result = {}; root = Path(root); device = root.stat().st_dev
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        r.require(info.st_dev == device and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'backup-tree-special-or-mounted')
        value = {'mode':stat.S_IMODE(info.st_mode), 'uid':info.st_uid, 'gid':info.st_gid,
                 'kind':'directory' if stat.S_ISDIR(info.st_mode) else 'file',
                 'xattrs':{name:os.getxattr(path,name,follow_symlinks=False).hex()
                           for name in os.listxattr(path,follow_symlinks=False)}}
        if stat.S_ISREG(info.st_mode):
            value.update(size=info.st_size, links=info.st_nlink, sha256=file_hash(path))
        result[str(path.relative_to(root))] = value
    return result


def validate(plan):
    r.fields(plan, ('schema_version', 'run_id', 'boot_id', 'expires_at', 'luks_uuid',
                    'usb', 'cryptsetup', 'postgres', 'preserved_files'))
    r.require(plan['schema_version']=='kaiba.pilot-backup-hook/v1alpha1' and
              isinstance(plan['run_id'], str) and len(plan['run_id'])<=56 and r.LABEL.fullmatch(plan['run_id']), 'backup-plan')
    r.timestamp(plan['expires_at'])
    r.require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', plan['luks_uuid']), 'backup-luks-uuid')
    for field in ('cryptsetup','postgres'):
        r.require(isinstance(plan[field],str) and plan[field].startswith('/nix/store/') and
                  '..' not in Path(plan[field]).parts, 'backup-tool-path')
    r.require(plan['cryptsetup'].endswith('/bin/cryptsetup') and plan['postgres'].endswith('/bin'), 'backup-tool-role')
    usb=plan['usb'];r.fields(usb, ('path','uuid','serial','disk_size','partition_size'))
    r.require(re.fullmatch(r'/dev/disk/by-id/usb-[A-Za-z0-9_+.:=-]+-part[0-9]+', usb['path']), 'backup-usb-path')
    r.require(isinstance(usb['serial'],str) and usb['serial'] and isinstance(usb['uuid'],str) and usb['uuid'], 'backup-usb-identity')
    r.require(type(usb['disk_size']) is int and type(usb['partition_size']) is int and
              usb['disk_size']>=usb['partition_size']>SIZE, 'backup-usb-size')
    files=plan['preserved_files'];r.require(isinstance(files,dict) and 0<len(files)<=256, 'backup-preserved-files')
    for path,digest in files.items():
        r.require(isinstance(path,str) and not Path(path).is_absolute() and
                  '..' not in Path(path).parts and isinstance(digest,str) and r.HEX.fullmatch(digest), 'backup-preserved-file')


class Backup:
    def __init__(self, plan):
        validate(plan); self.plan=r.decode(r.canonical(plan))
        self.state=Path('/var/lib')/('kaiba-backup-'+plan['run_id'])
        self.usb=Path('/run')/('kaiba-backup-'+plan['run_id'])
        self.restore=Path('/run')/('kaiba-restore-'+plan['run_id'])
        self.restore_name='kaiba-restore-'+plan['run_id']
        self.restore_mapper=Path('/dev/mapper')/self.restore_name
        self.destination=self.usb/('kaiba-backup-'+plan['run_id'])/'authority.luks'

    def guard(self):
        r.require(os.geteuid()==0, 'backup-root-required')
        r.require(time.time()<r.timestamp(self.plan['expires_at']), 'backup-expired')
        r.require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.plan['boot_id'], 'backup-host-rebooted')
        r.require(len(Path('/proc/swaps').read_text().splitlines())==1, 'backup-swap-active')

    def call(self, argv):
        self.guard()
        timeout=min(120, r.timestamp(self.plan['expires_at'])-time.time())
        r.require(timeout>0, 'backup-expired')
        result=subprocess.run(list(map(str,argv)), stdin=subprocess.DEVNULL, capture_output=True,
                              close_fds=True, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, timeout=timeout)
        r.require(result.returncode==0 and len(result.stdout)<=4*1024*1024, 'backup-command-failed')
        return result.stdout

    def record(self, name, value):
        raw=r.canonical(value)
        fd=os.open(self.state/(name+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:
            out.write(raw);out.flush();os.fsync(out.fileno())
        fd=os.open(self.state,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def stage(self, name, argv):
        self.guard();self.record(name+'.intent', {'stage':name})
        self.call(argv);self.record(name+'.complete', {'status':'completed'})

    def mounts(self):
        return r.decode(self.call(['/usr/bin/findmnt','--json','--list','-o','TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN']))['filesystems']

    def stopped(self):
        for unit in SERVICES:
            r.require(self.call(['/usr/bin/systemctl','show',unit,'--property=ActiveState','--value']).strip()==b'inactive', 'backup-writer-not-stopped')
        r.require(not (SOURCE/'postgres/data/postmaster.pid').exists(), 'backup-postgres-pid-present')

    def mapping(self, mapper, image, readonly):
        info=mapper.stat();r.require(stat.S_ISBLK(info.st_mode), 'backup-mapper-not-block')
        device=f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}';node=Path('/sys/dev/block')/device
        expected='CRYPT-LUKS2-'+self.plan['luks_uuid'].replace('-','')+'-'+mapper.name
        r.require((node/'dm/uuid').read_text().strip()==expected and
                  (node/'ro').read_text().strip()==('1' if readonly else '0'), 'backup-mapper-identity')
        slaves=list((node/'slaves').iterdir());r.require(len(slaves)==1, 'backup-mapper-backing')
        backing=Path('/'+(slaves[0]/'loop/backing_file').read_text().strip().lstrip('/'))
        r.require(backing.resolve()==image.resolve(), 'backup-mapper-backing')
        return device

    def usb_identity(self):
        expected=self.plan['usb']
        disks=r.decode(self.call(['/usr/bin/lsblk','--tree','-J','-b','-e','7','-o','PATH,TYPE,SIZE,TRAN,SERIAL,UUID,FSTYPE']))['blockdevices']
        matches=[d for d in disks if (d.get('serial') or '').strip()==expected['serial']]
        r.require(len(matches)==1, 'backup-usb-ambiguous')
        disk=matches[0]
        r.require(disk['tran']=='usb' and disk['type']=='disk' and disk['size']==expected['disk_size'], 'backup-usb-disk')
        parts=[p for p in disk.get('children',[]) if p.get('uuid')==expected['uuid'] and
               p.get('fstype')=='vfat' and p['size']==expected['partition_size']]
        path=Path(expected['path']);r.require(len(parts)==1 and path.resolve()==Path(parts[0]['path']), 'backup-usb-partition')
        info=path.stat();r.require(stat.S_ISBLK(info.st_mode), 'backup-usb-not-block')
        return f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'

    def mounted(self, target, device, flags, kind='ext4'):
        rows=[x for x in self.mounts() if x['target']==str(target)]
        r.require(len(rows)==1 and rows[0]['maj:min']==device and rows[0]['fstype']==kind and
                  flags<=set(rows[0]['options'].split(',')), 'backup-mount-mismatch')
        r.require(not any(x['target'].startswith(str(target)+'/') for x in self.mounts()), 'backup-nested-mount')

    def database(self, root):
        control=self.call([self.plan['postgres']+'/pg_controldata',root/'postgres/data']).decode()
        fields=dict(line.split(':',1) for line in control.splitlines() if ':' in line)
        r.require(fields.get('Database cluster state','').strip()=='shut down' and
                  fields.get('Data page checksum version','').strip()=='1', 'backup-database-state')

    def image_identity(self):
        info=IMAGE.lstat()
        r.require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and
                  stat.S_IMODE(info.st_mode)==0o600 and info.st_size==SIZE,'backup-image-metadata')
        return info.st_dev,info.st_ino,info.st_size

    def run(self, keyfd):
        r.require(type(keyfd) is int and keyfd>2 and stat.S_ISFIFO(os.fstat(keyfd).st_mode), 'backup-key-not-pipe')
        self.keyfd=keyfd
        try:return self._run()
        finally:
            if self.keyfd is not None:
                os.close(self.keyfd);self.keyfd=None

    def _run(self):
        self.guard();os.umask(0o077)
        for parent in (self.state.parent,self.usb.parent,IMAGE.parent,SOURCE.parent):r.trusted_parent(parent,0)
        for path in (self.state,self.usb,self.restore,self.restore_mapper):r.require(not os.path.lexists(path),'backup-attempt-or-scratch-exists')
        identity=self.image_identity()
        self.stopped();source_dev=self.mapping(MAPPER,IMAGE,False)
        flags={'rw','nosuid','nodev','noexec'};self.mounted(SOURCE,source_dev,flags)
        self.database(SOURCE)
        for path,digest in self.plan['preserved_files'].items():
            current=SOURCE
            for component in Path(path).parts[:-1]:
                current=current/component;info=current.lstat()
                r.require(stat.S_ISDIR(info.st_mode) and info.st_dev==SOURCE.stat().st_dev and
                          not info.st_mode&0o022,'backup-preserved-parent')
            r.require(file_hash(SOURCE/path)==digest,'backup-preserved-input-changed')
        usbdev=self.usb_identity()
        r.require(not any(x['maj:min']==usbdev for x in self.mounts()),'backup-usb-already-mounted')
        self.state.mkdir(mode=0o700);self.record('plan',self.plan)
        self.record('backup.intent',{'source_identity':identity,'plan_sha256':r.sha(r.canonical(self.plan))})
        self.usb.mkdir(mode=0o700)
        options='nosuid,nodev,noexec,uid=0,gid=0,fmask=0077,dmask=0077'
        self.stage('usb-mount',['/usr/bin/mount','-t','vfat','-o','ro,'+options,self.plan['usb']['path'],self.usb])
        self.mounted(self.usb,usbdev,{'ro','nosuid','nodev','noexec'},'vfat')
        r.require(not os.path.lexists(self.destination.parent),'backup-destination-exists')
        fs=os.statvfs(self.usb);r.require(fs.f_bavail*fs.f_frsize>SIZE+64*1024*1024,'backup-usb-space')
        self.stopped();expected=snapshot(SOURCE)
        self.stage('source-unmount',['/usr/bin/umount',SOURCE])
        r.require(not any(x['maj:min']==source_dev for x in self.mounts()),'backup-source-still-mounted')
        self.mapping(MAPPER,IMAGE,False)
        self.stage('usb-remount',['/usr/bin/mount','-o','remount,rw,'+options,self.usb])
        self.mounted(self.usb,usbdev,flags,'vfat');r.require(self.usb_identity()==usbdev,'backup-usb-changed')
        self.destination.parent.mkdir(mode=0o700)
        self.record('copy.intent',{'bytes':SIZE})
        digest=copy_exclusive(IMAGE,self.destination,SIZE)
        info=IMAGE.lstat();r.require((info.st_dev,info.st_ino,info.st_size)==identity and
                file_hash(IMAGE)==digest and file_hash(self.destination)==digest,'backup-readback-failed')
        self.record('copy.complete',{'sha256':digest})
        r.require(self.call([self.plan['cryptsetup'],'luksUUID',self.destination]).decode().strip()==self.plan['luks_uuid'],'backup-copy-uuid')
        self.guard();self.record('recovery-open.intent',{'mode':'readonly','slot':0})
        keyfd=self.keyfd;self.keyfd=None  # transfer ownership; never close a reused FD
        recovery.consume(self.plan['cryptsetup'],self.destination,keyfd,mapper=self.restore_name,
                         timeout=max(1,min(120,int(r.timestamp(self.plan['expires_at'])-time.time()))))
        restore_dev=self.mapping(self.restore_mapper,self.destination,True)
        self.restore.mkdir(mode=0o700)
        self.stage('restore-mount',['/usr/bin/mount','-t','ext4','-o','ro,noload,nosuid,nodev,noexec',self.restore_mapper,self.restore])
        self.mounted(self.restore,restore_dev,{'ro','nosuid','nodev','noexec'})
        r.require(snapshot(self.restore)==expected,'backup-restored-tree-mismatch')
        self.database(self.restore)
        self.stage('database-checksums',[self.plan['postgres']+'/pg_checksums','--check','-D',self.restore/'postgres/data'])
        self.stage('restore-unmount',['/usr/bin/umount',self.restore])
        self.stage('restore-close',[self.plan['cryptsetup'],'close',self.restore_name])
        r.require(not self.restore_mapper.exists(),'backup-restore-mapper-remains');self.restore.rmdir()
        r.require(file_hash(IMAGE)==digest and file_hash(self.destination)==digest,'backup-ciphertext-changed')
        result={'status':'passed','plan_sha256':r.sha(r.canonical(self.plan)),'bytes':SIZE,'sha256':digest,
                'recovery_passphrase_test':'passed','restoration':'file content/metadata/xattrs and database checksums',
                'services_started':False,'full_qualification':False}
        fd=os.open(self.destination.parent/'manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:out.write(r.canonical(result));out.flush();os.fsync(out.fileno())
        self.stage('usb-unmount',['/usr/bin/umount',self.usb])
        r.require(not any(x['maj:min']==usbdev for x in self.mounts()),'backup-usb-still-mounted');self.usb.rmdir()
        self.stage('source-remount',['/usr/bin/mount','-t','ext4','-o','nosuid,nodev,noexec',MAPPER,SOURCE])
        self.mounted(SOURCE,source_dev,flags);self.mapping(MAPPER,IMAGE,False);self.stopped()
        self.record('result',result)
        return result
