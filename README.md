# metasploit_eternal_doublepulsar
Metasploit Eternal Doublepulsar National Security Agency (NSA) Leak Tool (2017)

first, you need install Metasploit<br>
<a href="https://www.darkoperator.com/installing-metasploit-in-ubunt">https://www.darkoperator.com/installing-metasploit-in-ubunt</a><br>
<a href="https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html">https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html</a>

Install wine
```
sudo dpkg --add-architecture i386
sudo apt update
sudo apt-get install wine32 wine64
```

file permissions
```
chmod +x -R metasploit_eternal_doublepulsar
cd metasploit_eternal_doublepulsar
```


move exploit on metasploit file

Ubuntu
```
sudo mv *.rb /opt/metasploit-framework/embedded/framework/modules/exploits/windows/smb/
```

Kali Linux
```
sudo mv *.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/
```

Parrot OS
```
sudo mv *.rb /opt/metasploit-framework/embedded/framework/modules/exploits/windows/smb/
```
move some file
```
sudo mv Eternal /opt/Eternal
```
run msfconsole (Metasploit)

<img src="https://github.com/rouze-d/metasploit_eternal_doublepulsar/blob/main/screenshot/01.png">
<img src="https://github.com/rouze-d/metasploit_eternal_doublepulsar/blob/main/screenshot/02.png">
<img src="https://github.com/rouze-d/metasploit_eternal_doublepulsar/blob/main/screenshot/03.png">
