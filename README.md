lobbyemu
========

.hack//frägment Lobby Server Emulator

Change log:
3/24/2014 - Fixed errors for compiling in cygwin,centos,etc. apparently my normal dev machine doesn't think it needs to let me know about these kinds of things. (NCDyson)


3/21/2014 - More changes. Code is kind of a mess right now. Here's the highlights. (NCDyson)

		"Online" Mode:
			ALTIMIT DESKTOP:
				Figured out that there's a welcome message that can be displayed. I believe you only get like 260 characters. There's also a way to make it no appear, I just don't remember how right this second.
				
				News System:
					Returns Error. Still working out the specifics of the actual news posts, then we'll be good to go.

				Mail System:
					Returns no new mail. Don't try to send a message. It will not work.
					
			The World:
				Guild:
					Stay away. Haven't even started investigating.
					
				Ranking:
					Stay Away. Haven't even started investigating.
					
				BBS:
					Stay Away. In the middle of investigating.
					
				Lobby:
					Follow the Menus until you get to the screen with the user list. Press Triangle, then select the first option.
					Follow the menu again, and you're at the Area Server list. So long as your area server is set to connect to your lobby server, and your area server has had the DISKID(which is still going to be all 0's) transfered, you should be able to connect your area server and see it in this list. I believe I have enough of the packets implemented so that the server's status gets updated properly. Just hit Square and then Circle to refresh the list.
					
					The code is set up to send the Area Server's LAN IP if the Game's External IP and the Area Server's External IP are the same, other wise it's supposed to send the Area Server's External IP. I haven't had a chance to test this out yet though.
					
					The Lobby is going to say there's 0 users, and the Player List is going to be empty. I haven't implemented for tracking which users are in the lobby, and I'm still working on the player list, which you can tell from the code. 
					
					Speaking of which, on the screen with the Player list, in the Menu you get by pressing Triangle, stay away from the other two options. One is a Recent servers list, which will display recent servers, but it doesn't quite work right yet.
					
					The other is a chat room list, which I haven't investigated either.
					
			Misc Notes:
				I've been trying to clean up the code a little and document the data that goes into the packets as I go, but sometimes I just get in the zone and forget to do this.
				
				You're going to see some stuff referencing SQLITE3 in the code. Since my computer and the PCSX2 networking plugin don't get along as famously as I would like, my main development device for the server is my android tablet.I didn't have a mysql library availble to work with, so when I was taking a break from figuring out the Area Server -> Lobby Server stuff, I was dabbling in database stuff for the BBS,News and Mail systems. 






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