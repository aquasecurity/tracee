package benchmarks

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters"
)

func matchFilter(fils []string, argValStr string) bool {
	for _, f := range fils {
		prefixCheck := f[len(f)-1] == '*'
		if prefixCheck {
			f = f[0 : len(f)-1]
		}
		suffixCheck := f[0] == '*'
		if suffixCheck {
			f = f[1:]
		}
		if argValStr == f ||
			(prefixCheck && !suffixCheck && strings.HasPrefix(argValStr, f)) ||
			(suffixCheck && !prefixCheck && strings.HasSuffix(argValStr, f)) ||
			(prefixCheck && suffixCheck && strings.Contains(argValStr, f)) {
			return true
		}
	}
	return false
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// generate random strings with 50% to match a prefix
func randStringRunes(n int, fs []string) string {
	symbols := []string{}
	for _, filter := range fs {
		symbol := strings.TrimSuffix(filter, "*")
		symbol = strings.TrimPrefix(symbol, "*")
		symbols = append(symbols, symbol)
	}
	b := make([]rune, n)
	c := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
		c[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	num := rand.Intn(101)
	str := string(b)
	str2 := string(c)
	if num < 25 {
		return str
	}
	if num < 50 {
		return str + selectRandomElement(symbols) + str2
	}
	if num < 75 {
		return str + selectRandomElement(symbols)
	}

	return selectRandomElement(symbols) + str
}

func selectRandomElement(list []string) string {
	return list[rand.Intn(len(list))]
}

var filterVals = []string{
	"/etc/rc.local", "/etc/init.d/rc.local", "/etc/rc1.d*", "/etc/rc2.d*", "/etc/rc3.d*", "/etc/rc4.d*", "/etc/rc5.d*", "/etc/rc6.d*", "/etc/rcs.d*", "/etc/init.d*", "/etc/rc.d/rc.local*", "/etc/rc.d/init.d*", "/etc/rc.d*", "*nr_hugepages", "*free_hugepages", "*/sys/module/msr/parameters/allow_writes", "*/etc/ld.so.preload", "/proc/sys/kernel/sysrq", "/proc/sysrq-trigger", "/etc/sudoers", "/private/etc/sudoers", "/etc/sudoers.d/*", "/private/etc/sudoers.d/*", "*docker.sock", "core_pattern", "*kubeadm-kubelet-config.yaml", "*kubelet.conf", "*/kubelet/config.yaml", "*kubelet-config.yaml", "*/sched_debug", "/*kube*config", "/sys/kernel/debug/kprobes/enabled", "notify_on_release", "*git/credentials/*", "*config/google-chrome/default/login", "data*", "*/.ssh/*", "*.npmrpc", "*.git-credentials", "*key4.db", "*logins.json", "*authorized_keys", "/etc/selinux*", "/selinux*", "/etc/sysconfig/selinux*", "*/etc/shadow", "*/etc/profile", "*/etc/master.passwd", "*/etc/shells", "*/etc/netsvc.conf", "*.dockerignore", "release_agent", "/etc/crontab", "/etc/anacrontab", "/etc/cron.deny", "/etc/cron.allow", "/etc/cron.hourly*", "/etc/cron.daily*", "/etc/cron.weekly*", "/etc/cron.monthly*", "/etc/cron.d*", "/var/spool/cron/crontabs*", "var/spool/anacron*", "/proc*mem", "/etc/kubernetes/pki/*", "*identity.pub", "*id_rsa.pub", "*id_rsa", "*ssh_config", "*id_dsa.pub", "*id_dsa", "*sshd_config", "*ssh_host_dsa_key.pub", "*ssh_host_dsa_key", "*ssh_host_rsa_key.pub", "*ssh_host_rsa_key", "*ssh_host_key.pub", "*ssh_host_key", "*/python*", "*/dist-packages/*", "/etc/shadow", "/*secrets/kubernetes.io/serviceaccount*", "/var/spool/cron/crontabs", "var/spool/anacron", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d", "/proc/kcore", "/proc/sys/kernel/randomize_va_space", "*.bash_profile", "*.bashrc", "*.bash_logout", "*.bash_login", "/etc/profile.d*", "/etc/profile*", "/etc/bashrc*", "*.profile", "/home/*", "/root/*",
}

func BenchmarkStringFilter10(b *testing.B) {
	benchmarkStringFilter(b, 10)
}

func BenchmarkStringFilter50(b *testing.B) {
	benchmarkStringFilter(b, 50)
}

func BenchmarkStringFilter100(b *testing.B) {
	benchmarkStringFilter(b, 100)
}

func BenchmarkMatchFilter10(b *testing.B) {
	benchmarkMatchFilter(b, 10)
}

func BenchmarkMatchFilter50(b *testing.B) {
	benchmarkMatchFilter(b, 50)
}
func BenchmarkMatchFilter100(b *testing.B) {
	benchmarkMatchFilter(b, 100)
}

func benchmarkStringFilter(b *testing.B, len int) {
	filter := filters.NewStringFilter(nil)
	err := filter.Parse(fmt.Sprintf("=%s", strings.Join(filterVals, ",")))
	require.NoError(b, err)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Filter(randStringRunes(len, filterVals))
	}
}

func benchmarkMatchFilter(b *testing.B, len int) {
	for n := 0; n < b.N; n++ {
		matchFilter(filterVals, randStringRunes(len, filterVals))
	}
}
