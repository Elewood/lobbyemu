lobbyemu
========

.hack//frägment Lobby Server Emulator

Change log:
3/5/2014 - Too many changes to really list out, so I'll go over what currently works. (NCDyson)
General:
	In Client.cpp you can enable logging of incoming 0x30 packets by setting "enableLogging = true" in constructor. It's a quick and dirty addition that makes it a lot easier to look at the strings/other data coming in off the packets. It's explicitly set to false right now, as I wouldn't describe myself as even remotely good at C++. Also, it tends to generate a lot of logs when you have a "run, connect, connect, connect, change, compile, run, connect, connect, connect" kind of work flow. 

"Online" Mode:
	Game will connect to Lobby Server.
	Game sends DISKID, Lobby blindly sends OK.
	Game sends SAVEID, Lobby blindly sends OK.
	Game will do other communications, Lobby will blindly send OK.
	
	Game goes to ALTIMIT DESKTOP.
	Game checks for NEWS/MAIL, Lobby sends OK/NONE.
	
	Going to NEWS from DESKTOP, Lobby sends OK/NONE. List will be blank.
	Going to MAIL->Server Online, Selecting "Check Mail", Lobby sends OK/NONE. Game will display "There was no new mail"
	Creating a draft and trying to send, Lobby will not be able to respond and eventually game will disconnect.
	Going to "The World":
		After Creating character, Game sends REGISTER_CHARACTER. Lobby blindly sends OK.
		After Deleting character, Game sends UNREGISTER_CHARACTER. Lobby blindly sends OK.
		
		Selecting character, communications eventually lead to message "Character Data corruption has been detected. try online mode again."
			Game returns to Title.


"Area Server" Mode: 
	Game will connect to Lobby Server, verify DISKID, and other communications, then disconnects.
	Game will then show screen to enter IP Address and port of Area Server.
	Game connects to Area Server, presumably to transfer over DISKID. Specifics of communication have yet to be investigated.
	
	
Area Server(PC side):
	After transfering DISKID, Area Server will then try to connect to Lobby. At this point, only the initial LOGON packet is correctly(?) responded to.