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

%w[calc_speed calc_cpu].each do |name|
  eval(source[/^def #{name}[^\n]*\n.*?^end$/m], TOPLEVEL_BINDING)
end
@hstats = [[1, 'i', '7', 'CPU0', 'test']]
@stats = [[4, 'i', '7', 'CPU0', 'test']]
@dt = 0.0
calc_speed
check(@s[0][0] == 0.0 && @t['CPU0'] == 0.0)
@dt = 0.5
calc_speed
check(@s[0][0] == 6.0)
@hcstat = {'cpu0' => [0] * 7}
@cstat = {'cpu0' => [0] * 7}
calc_cpu
check(@cBusy['CPU0'] == 0 && @cHIrq['CPU0'] == 0 && @cSIrq['CPU0'] == 0)
@cstat = {'cpu0' => [2, 0, 1, 5, 1, 1, 0]}
calc_cpu
check(@cBusy['CPU0'] == 40.0 && @cHIrq['CPU0'] == 10.0)
require 'getoptlong'
options = source[source.index('@imode =')...source.index('def read_table')]
[[[], 5], [['-d', '0.5'], 0.5], [['0.25'], 0.25], [['-d', '1.25', '3'], 1.25]].each do |args, expected|
  @delay = nil
  ARGV.replace(args)
  eval(options, TOPLEVEL_BINDING)
  check(@delay == expected)
end
%w[0 -1 garbage 1e999].each do |bad|
  @delay = nil
  ARGV.replace(['-d', bad])
  begin
    eval(options, TOPLEVEL_BINDING)
    raise 'invalid delay accepted'
  rescue SystemExit => e
    check(!e.success?)
  end
end
puts 'irqtop fractional delay and zero interval checks passed'
