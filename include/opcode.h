#ifndef _OPCODE_H_
#define _OPCODE_H_

#define OPCODE_PING 0x02
#define OPCODE_DATA 0x30
#define OPCODE_KEY_EXCHANGE_REQUEST 0x34
#define OPCODE_KEY_EXCHANGE_RESPONSE 0x35
#define OPCODE_KEY_EXCHANGE_ACKNOWLEDGMENT 0x36




//lobby defines...

//0x30_0x7862


/*
struct packet0x30_0x7862
{
	uint16_t lobbyEventType
	uint16_t unkStrLen
	...
}


struct packet0x30_0x7862
//when Event Type == 0x01
//User enters.
{
	uint16_t lobbyEventType = 0x01;
	uint16_t unkStrLen = 12; //0x0c
	uint8_t  dataType;
	char unkStr[unkStrLen]; //I'm not entirely sure this is even a string...
	uint16_t dataLen;
	char data[dataLen]; //it includes null terminator...
}

struct packet0x30_0x7862
//when EventType == 0x02
//Tell?
{
	uint16_t lobbyEventType = 0x02;
	uint16_t unkStrLen = 12; //0x0c
	char unkStr[unkStrLen]; //still not sure it's a string...
	uint16_t dataLen;
	char data[dataLen];	//it includes null terminator, this is what to tell the other user.
}
	
//lobbyEventType = 0x01:
//	User Enters.
dataType 4 = userName
dataType 5 = userGreeting


//lobbyEventType = 0x02:
//	Tell?



*/




#define LOBBY_USER_ENTER		0x01
#define LOBBY_USER_TELL		 0x02



//There's several packets that come in when a user enters,
#define LOBBY_USER_ENTER_NAME   0x4
#define LOBBY_USER_ENTER_GREETING 0x5


//MISC_DEFINES
#define CLIENTTYPE_GAME		    0x7430
#define CLIENTTYPE_AREASERVER		0x7431
#define CLIENTTYPE_WEBCLIENT	0x7432

//Packet 0x30 subOpcode Defines
//The area server likes to ping in a DATA packet...
#define OPCODE_DATA_PING			 0x02

//Nice to know.
#define OPCODE_DATA_SERVERKEY_CHANGE 0x31

//Not sure that's actually what this does.
#define OPCODE_DATA_PING2 			0x40
#define OPCODE_DATA_PONG2 			0x41


#define OPCODE_DATA_LOGON_REPEAT	0x7000
#define OPCODE_DATA_LOGON_RESPONSE  0x7001

//check and see if there's new posts on the BBS?
#define OPCODE_DATA_BBS_GET_UPDATES	0x786a



#define OPCODE_DATA_LOBBY_ENTERROOM 0x7006
#define OPCODE_DATA_LOBBY_ENTERROOM_OK 0x7007

#define OPCODE_DATA_LOBBY_CHATROOM_GETLIST 		  0x7406
#define OPCODE_DATA_LOBBY_CHATROOM_CATEGORY    	  0x7407
#define OPCODE_DATA_LOBBY_CHATROOM_LISTERROR         0x7408
//not seen?
#define OPCODE_DATA_LOBBY_CHATROOM_ENTRY_CATEGORY	0x7409
#define OPCODE_DATA_LOBBY_CHATROOM_CHATROOM		  0x740a
#define OPCODE_DATA_LOBBY_CHATROOM_ENTRY_CHATROOM	0x740b



#define OPCODE_DATA_LOBBY_CHATROOM_CREATE				0x7415
#define OPCODE_DATA_LOBBY_CHATROOM_CREATE_OK	     0x7416
#define OPCODE_DATA_LOBBY_CHATROOM_CREATE_ERROR 0x7417

//Why?
#define OPCODE_DATA_LOGON_AS2	   	0x7019
//Doesn't work
#define OPCODE_DATA_LOGON_AS2_RESPONSE 0x701d

#define OPCODE_DATA_DISKID		   0x7423
/*
struct diskiddata
{
	char discID[65]; // might be variable, but so far only 64 byte (+1B null terminator) were encountered
	char static[9]; // might be variable, but so far only 8 byte (+1B null terminator) were encountered, value seems to be a static "dot_hack" string
};
*/
#define OPCODE_DATA_DISKID_OK		0x7424
#define OPCODE_DATA_DISKID_BAD	   0x7425

#define OPCODE_DATA_SAVEID		   0x7426
#define OPCODE_DATA_SAVEID_OK	    0x7427
//#define OPCODE_DATA_SAVEGAME_BAD	 0x7428
	//replies back with 0x7429, with no argument.


#define OPCODE_DATA_LOBBY_EXITROOM	0x7444
#define OPCODE_DATA_LOBBY_EXITROOM_OK 0x7445

#define OPCODE_DATA_REGISTER_CHAR	 0x742B
/*
struct registerChar
{
	uint8_t saveSlot; // 0-2
	char saveID[21] //includes null terminator
	char name[]; //variable length. includes null terminator.
	uint8_t class; // 0 = Twin Blade, 1 = Blademaster, 2 = Heavy Blade, 3 = Heavy Axe, 4 = Long Arm, 5 = Wavemaster
	uint16_t level;
	char greeting[]; //var len, null term.

	uint32_t model; // this code follows ncdysons formula as seen in client.cpp
	uint8_t unk1; // 0x01?
	uint16_t hp;
	uint16_t sp;
	uint32_t gp;
	uint16_t offlineGodCounter;
	uint16_t onlineGodCounter;
	uint16_t unk2; // maybe some kind of story completion bit?

	uint8_t unk4[44];
}
*/


#define OPCODE_DATA_REGISTER_CHAROK   0x742C

#define OPCODE_DATA_UNREGISTER_CHAR   0x7432
#define OPCODE_DATA_UNREGISTER_CHAROK 0x7433

#define OPCODE_DATA_RETURN_DESKTOP	0x744a
#define OPCODE_DATA_RETURN_DESKTOP_OK 0x744b


//main lobby...
#define OPCODE_DATA_LOBBY_GETMENU		0x7500
#define OPCODE_DATA_LOBBY_CATEGORYLIST	 0x7501 // uint16_t numberOfCategories
#define OPCODE_DATA_LOBBY_GETMENU_FAIL   0x7502 //Failed to get list
#define OPCODE_DATA_LOBBY_ENTRY_CATEGORY    0x7503 //uint16_t categoryNum, char* categoryName
#define OPCODE_DATA_LOBBY_LOBBYLIST	     0x7504 //uint16_t numberOfLobbies
#define OPCODE_DATA_LOBBY_ENTRY_LOBBY	   0x7505 //uint16_t lobbyNum, char* lobbyName, uint32_t numUsers (?)


//LOBBY_EVENT?
#define OPCODE_DATA_LOBBY_EVENT			0x7862


#define OPCODE_DATA_LOBBY_GETSERVERS     0x7841
#define OPCODE_DATA_LOBBY_GETSERVERS_OK  0x7842

//ANOTHER Tree
#define OPCODE_DATA_LOBBY_GETSERVERS_GETLIST	0x7506	
#define OPCODE_DATA_LOBBY_GETSERVERS_CATEGORYLIST  0x7507 //arg is # items?
#define OPCODE_DATA_LOBBY_GETSERVERS_FAIL  0x7508   //FAILED
#define OPCODE_DATA_LOBBY_GETSERVERS_ENTRY_CATEGORY  0x7509 //The DIRS
#define OPCODE_DATA_LOBBY_GETSERVERS_SERVERLIST  0x750a //arg is # items?
#define OPCODE_DATA_LOBBY_GETSERVERS_ENTRY_SERVER  0x750b //yay...


#define OPCODE_DATA_LOBBY_GETSERVERS_EXIT 	  0x7844
#define OPCODE_DATA_LOBBY_GETSERVERS_EXIT_OK	0x7845	

#define OPCODE_DATA_NEWS_GETMENU     			0x784e
#define OPCODE_DATA_NEWS_CATEGORYLIST    0x784f //arg is #of items in category list
#define OPCODE_DATA_NEWS_GETMENU_FAILED  		0x7850 //Failed
#define OPCODE_DATA_NEWS_ENTRY_CATEGORY	 0x7851 //Category list Entry
#define OPCODE_DATA_NEWS_ARTICLELIST   	0x7852 //Article list, Arg is # entries
#define OPCODE_DATA_NEWS_ENTRY_ARTICLE	  0x7853 //Article List Entry
//7853 - ok/no data
//7852 - ok/wants more data?
//7851 - ok/no data?
//7850 - failed
//784f - ok



#define OPCODE_DATA_NEWS_GETPOST		0x7854

#define OPCODE_DATA_NEWS_SENDPOST	   0x7855
//7856
//7857
//7855


#define OPCODE_DATA_MAIL_GET        0x7803
#define OPCODE_DATA_MAIL_GETOK     0x7804



//BBS	POSTING	STUFF
#define OPCODE_DATA_BBS_GETMENU		0x7848
#define OPCODE_DATA_BBS_CATEGORYLIST   0x7849
#define OPCODE_DATA_BBS_GETMENU_FAILED 0x784a
#define OPCODE_DATA_BBS_ENTRY_CATEGORY 0x784b
#define OPCODE_DATA_BBS_THREADLIST	 0x784c
#define OPCODE_DATA_BBS_ENTRY_THREAD   0x784d	
			//7849 threadCat
			//784a error
			//784b catEnrty
			//784c threadList
			//784d threadEnrty			
			
#define OPCODE_DATA_BBS_THREAD_GETMENU         0x7818
#define OPCODE_DATA_BBS_THREAD_LIST			0x7819
#define OPCODE_DATA_BBS_THREAD_GETMENU_FAILED  0x781a
#define OPCODE_DATA_BBS_THREAD_ENTRY_POST	  0x781b
//7819
//781a
//781b




//These happen upon entering ALTIMIT DESKTOP
#define OPCODE_DATA_MAILCHECK			 0x7867
#define OPCODE_DATA_MAILCHECK_OK		  0x7868
#define OPCODE_DATA_MAILCHECK_FAIL		0x7869
//
#define OPCODE_DATA_NEWCHECK			0x786D
#define OPCODE_DATA_NEWCHECK_OK		 0x786e
//

#define OPCODE_DATA_COM			  0x7876
#define OPCODE_DATA_COM_OK		   0x7877

#define OPCODE_DATA_SELECT_CHAR	   0x789f
/*
struct selectchar
{
	char discID[65]; // most likely variable size, but we only encounter 64byte (+1B null terminator) really
	char systemSaveID[21]; // most likely variable size, but we only encounter 20byte (+1B null terminator) really
	uint8_t unk1; // same as unk1 in OPCODE_DATA_REGISTER_CHAR
	char characterSaveID[21]; // most likely variable size, but we only encounter 20 byte (+1B null terminator) really
};
OPCODE_DATA_SELECT_CHAR is a variable size packet with 3 null terminated strings appended to each others end.

ex. "1234ABCD\0DEADBEEF\0C01DB15D\0"

They seem to be hex values represented in ascii, like this "0e041409..." and so on.

The first string seems to be the disc id and usually is 0x40 (0x41 with terminator) bytes long, representing a 32byte hex value.
Due to the way we patched the disc id (DNAS) out of the iso, every user has the same value here for now, namely all zero bytes.

The second one seems to be the console / savedata id and probably corresponds to the system savedata file people create when they first launch fragment.

The third and final one is the character id and is created when people create a new character and reported to the server via the OPCODE_DATA_REGISTER_CHAR packet.
*/
#define OPCODE_DATA_SELECT_CHAROK	 0x78a0


#define OPCODE_DATA_SELECT2_CHAR	  0x78a2
/*
OPCODE_DATA_SELECT_CHAR2 seems to be a 1:1 clone of the normal OPCODE_DATA_SELECT_CHAR packet.
*/
#define OPCODE_DATA_SELECT2_CHAROK	0x78a3



#define OPCODE_DATA_LOGON		   	 0x78AB
//Area server doesn't like 0x7001
#define OPCODE_DATA_LOGON_RESPONSE_AS	0x78ad




#define OPCODE_DATA_MAIL_SEND			0x7800
/*
	DATA_MAIL_SEND PACKET DESC
	struct mailPacket
	{
		uint32_t unk1 = 0xFFFFFFFF
		uint32_t date;
		char * recipient;
		uint32_t unk2;
		uint16_t unk3;
		char * sender;
		char unk4;
		char subject[0x80];
		char text[0x47e];
		
		
		
		
		
		
	}
*/




#define OPCODE_DATA_BBS_POST		0x7812
/*
	DATA_BBS_POST	PACKET	DESC
	struct bbsPostPacket
	{
		uint32_t unk1 0x00000000
		char userName[0x4c];
		uint16_t unk2;
		uint16_t dSize; //data size...
		char title[0x32];		//message title
		char body[0x25a]; //message body. 602 chars. 


*/


#define OPCODE_DATA_MAIL_SEND_OK		0x7801


#define OPCODE_DATA_LOBBY_FAVORITES_AS_INQUIRY		0x7858
//sends the DISKID of the lobby server to get the status of... I think.


///////////////
//AREA	SERVER	DEFINES:
///////////////
#define OPCODE_DATA_AS_DISKID		0x785b
#define OPCODE_DATA_AS_DISKID_OK	 0x785c
#define OPCODE_DATA_AS_DISKID_FAIL   0x785d

#define OPCODE_DATA_AS_IPPORT		0x7013
#define OPCODE_DATA_AS_IPPORT_OK	 0x7014

#define OPCODE_DATA_AS_PUBLISH		0x78ae
#define OPCODE_DATA_AS_PUBLISH_OK	 0x78af


#define OPCODE_DATA_AS_PUBLISH_DETAILS1 	  0x7011
#define OPCODE_DATA_AS_PUBLISH_DETAILS1_OK    0x7012
//initial server details...
/*
	struct asPublishDetails1:
	{
		char diskID[65];
		char * serverName; //this is variable length, but no longer than 21 I believe, including null terminator.
		uint16_t serverLevel;
		uint16_t serverType;	//serverType
		uint16_t sUnk;	//I'm not sure what that's for yet.
		uint8_t sStatus;		//serverStatus.
		uint8_t serverID[8];
		//We don't really need to worry about the server type or status. the game know's what's up.
	}						
*/



#define OPCODE_DATA_AS_PUBLISH_DETAILS2	   0x7016
#define OPCODE_DATA_AS_PUBLISH_DETAILS2_OK	0x7017
//I'm still not sure what's up with this dude.


#define OPCODE_DATA_AS_PUBLISH_DETAILS3	   0x7881
#define OPCODE_DATA_AS_PUBLISH_DETAILS3_OK	0x7882

#define OPCODE_DATA_AS_PUBLISH_DETAILS4	   0x7887
#define OPCODE_DATA_AS_PUBLISH_DETAILS4_OK	0x7888

#define OPCODE_DATA_AS_UPDATE_USERNUM	   0x741d //uint32_t numUsers
#define OPCODE_DATA_AS_PUBLISH_DETAILS5_OK	0x741e
//update user num?



#define OPCODE_DATA_AS_PUBLISH_DETAILS6	   0x78a7
#define OPCODE_DATA_AS_PUBLISH_DETAILS6_OK    0x78a8

#define OPCODE_DATA_AS_UPDATE_STATUS	   0x780c
#define OPCODE_DATA_AS_PUBLISH_DETAILS7_OK    0x780d
/*
	struct asUpdatStatus:
	{
		uint16_t unk1;		//NO idea what this is about...
		char diskID[65];
		char * serverName; //this is variable length, but no longer than 21 I believe, including null terminator.
		uint16_t serverLevel;
		uint16_t serverType;	//serverType
		uint8_t sStatus;		//serverStatus.
		uint8_t serverID[8];
		//We don't really need to worry about the server type or status. the game know's what's up.
	}						
*/



//:3
#define OPCODE_DATA_AS_NAMEID		0x5778
#define OPCODE_DATA_AS_DISKID2	   0x78a7 //again?

/*
7011 diskid,name,unk,unk,id#
7016 uink
7881 diskid,id#,unk
7887 diskid,unk,name,id,unk
741d null
780c diskid,name,unk,unk,id#
78a7 diskid

	
		
*/	




#endif
