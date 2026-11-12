#!/usr/bin/env ruby
# SPDX-License-Identifier: GPL-2.0-only
source = File.read(File.expand_path('../irqtop', __dir__))
def check(condition)
  raise 'irqtop regression' unless condition
end
%w[read_affinity get_rps calc_rps].each do |name|
  eval(source[/^def #{name}[^\n]*\n.*?^end$/m], TOPLEVEL_BINDING)
end
IO.singleton_class.prepend(Module.new do
  def read(path, *args)
    return "00000001,00000000,ffffffff\n" if path.end_with?('/smp_affinity')
    return "00000000,80000000,00000001\n" if path.end_with?('rps_cpus')
    return "00000001,00000000,00000000\n" if path.end_with?('xps_cpus')
    super
  end
end)
Dir.singleton_class.prepend(Module.new do
  def glob(path, *args)
    return ['/proc/irq/7/smp_affinity'] if path == '/proc/irq/*/smp_affinity'
    super
  end
end)
read_affinity
check(@aff[7] == (1 << 64) + (1 << 32) - 1)
@showrps = true
@devlist = ['eth0']
@devre = Regexp.union(@devlist)
get_rps('eth0-rx-tx-0')
check(calc_rps(0) == '+')
check(calc_rps(31) == ' ')
check(calc_rps(63) == '+')
check(calc_rps(64) == '-')
puts 'irqtop CPU affinity checks passed'
