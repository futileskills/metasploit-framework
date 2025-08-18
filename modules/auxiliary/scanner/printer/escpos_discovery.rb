# encoding: utf-8
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ESC/POS Network Printer Discovery (Nmap-based)',
      'Description' => %q{
        Identifies network printers likely ESC/POS-compatible (e.g., Epson TM series,
        Star Micronics, BIXOLON). Uses a TCP 9100 scan and optionally sends a safe
        ESC/POS status query. Results are recorded in the Metasploit database.
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
    begin
      connect(true)
      print_status("#{ip}:#{rport} TCP open")
      escpos_resp = nil

      if datastore['ACTIVE_CHECK']
        sock.put(DLE_EOT1)
        sock.flush
        escpos_resp = sock.get_once(datastore['TIMEOUT'].to_i / 1000.0)
        escpos_resp = escpos_resp.bytes.map { |b| sprintf('0x%02X', b) }.join(' ') if escpos_resp
      end

      likely = escpos_resp || true # just open TCP/9100 is a hint
      if likely
        print_good("#{ip}: Likely ESC/POS printer (tcp/9100 open; escpos_resp=#{escpos_resp || 'none'})")
      end

      store_service(host: ip, port: rport, proto: 'tcp', name: 'printer-raw-9100')
      report_note(
        host: ip,
        type: 'printer.escpos.discovery',
        data: {
          escpos_candidate: likely,
          tcp_9100_open: true,
          escpos_status_bytes: escpos_resp
        },
        update: true
      )
    rescue ::Rex::ConnectionError
      vprint_status("#{ip}:#{rport} TCP closed")
    ensure
      disconnect rescue nil
    end
  end
end
