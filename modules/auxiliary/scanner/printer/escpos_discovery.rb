# encoding: utf-8
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ESC/POS Network Printer Discovery (Guaranteed Output)',
      'Description' => %q{
        Identifies network printers likely ESC/POS-compatible by checking TCP/9100
        and optionally sending a safe ESC/POS status query.
        Prints IPs immediately when discovered (thread-safe).
      },
      'Author'      => ['FutileSkills'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RHOSTS,
        Opt::RPORT(9100),
        OptInt.new('TIMEOUT', [true, 'TCP read timeout (ms)', 1000]),
        OptBool.new('ACTIVE_CHECK', [true, 'Send safe ESC/POS status (DLE EOT 1)', true]),
      ]
    )
  end

  DLE_EOT1 = "\x10\x04\x01".b

  def run_host(ip)
    likely = false

    begin
      connect(true)
      vprint_status("#{ip}:#{rport} TCP open")
      if datastore['ACTIVE_CHECK']
        sock.put(DLE_EOT1)
        sock.flush
        resp = sock.get_once(datastore['TIMEOUT'].to_i / 1000.0)
        likely = true if resp && !resp.empty?
      else
        likely = true
      end
    rescue ::Rex::ConnectionError
      vprint_status("#{ip}:#{rport} TCP closed")
      likely = false
    ensure
      disconnect rescue nil
    end

    if likely
      # Print immediately — guaranteed thread-safe
      puts "[ESC/POS] #{ip}"
    end
  end
end
