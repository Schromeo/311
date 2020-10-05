////////////////////////////////////////////////////////////////////////////////
//
//  File           : sg_driver.c
//  Description    : This file contains the driver code to be developed by
//                   the students of the 311 class.  See assignment details
//                   for additional information.
//
//   Author        : Yisong Cheng
//   Last Modified : Oct 5th,2020
//

// Include Files
#include <string.h>
#include <stdlib.h>
#include <time.h>
// Project Includes 
#include "sg_driver.h"

// Defines
#define UNIT_TEST_NUM 50

// Global Data

//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : serialize_sg_packet
// Description  : Serialize a ScatterGather packet (create packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - the block identifier
//                op - the operation performed/to be performed on block
//                sseq - the sender sequence number
//                rseq - the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status serialize_sg_packet( SG_Node_ID loc, SG_Node_ID rem, SG_Block_ID blk, 
        SG_System_OP op, SG_SeqNum sseq, SG_SeqNum rseq, char *data, 
        char *packet, size_t *plen ) {
	//Check
    if (loc==0)
    {
        return SG_PACKT_LOCID_BAD;
    }
    if (rem == 0)
    {
        return SG_PACKT_REMID_BAD;
    }
    if (blk==0)
    {
        return SG_PACKT_BLKID_BAD;
    }
	if (op >= SG_MAXVAL_OP)
	{
		return SG_PACKT_OPERN_BAD;
	}
	if (sseq == 0)
	{
		return SG_PACKT_SNDSQ_BAD;
	}
	if (rseq == 0)
	{
		return SG_PACKT_RCVSQ_BAD;
	}
    if (data==NULL)
    {
        return SG_PACKT_BLKDT_BAD;
    }
	
	/* Init */
	uint32_t magicValue = SG_MAGIC_VALUE;
    SG_Packet_Info* packInfo = (SG_Packet_Info*)malloc(sizeof(SG_Packet_Info));
    packInfo->locNodeId = loc;
    packInfo->remNodeId = rem;
    packInfo->blockID = blk;
    packInfo->operation = op;
    packInfo->sendSeqNo = sseq;
    packInfo->recvSeqNo = rseq;
	//packInfo->data=(SG_Data_Block*)malloc(sizeof(SG_Data_Block));
	//memcpy(*(packInfo->data),data,strlen(data)*sizeof(char));
	packInfo->data=NULL;
	//logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad op code (212)." );
	
	
	/*packet*/
	memcpy(packet, &magicValue, sizeof(magicValue));
	
	//logMessage( LOG_INFO_LEVEL, "test");
	//logMessage( LOG_INFO_LEVEL, *(packInfo->data) );
	char* infoPtr = packet + sizeof(magicValue);
	memcpy(infoPtr, packInfo, sizeof(SG_Packet_Info));
	//logMessage( LOG_INFO_LEVEL, *(((SG_Packet_Info*)infoPtr)->data));
	//logMessage( LOG_INFO_LEVEL, "test\n\n");
	char* dataPtr=infoPtr + sizeof(SG_Packet_Info);
	memcpy(dataPtr,data,strlen(data)+1);
	char* endMagicPtr = dataPtr + strlen(data)+1;

	memcpy(endMagicPtr, &magicValue, sizeof(magicValue));
	//(char*)(*((SG_Packet_Info*)infoPtr)->data)=dataPtr;

	/* plen */
	*plen = sizeof(SG_Packet_Info)+sizeof(magicValue)*2+strlen(data)+1;


	if(*((uint32_t*)(packet+*plen-sizeof(uint32_t))) == SG_MAGIC_VALUE)
	{
		logMessage( LOG_INFO_LEVEL, "SG_MAGIC_VALUE Success:%d %d %x", packet, *plen,*((uint32_t*)(packet+*plen-sizeof(uint32_t))));
	}

	return SG_PACKT_OK;
}


int checkPacket(char* packet,int plen)
{
	if(plen==0)
	{
		//logMessage( LOG_INFO_LEVEL, "2" );
		return 1;
	}
	if (packet==NULL)
	{
		//logMessage( LOG_INFO_LEVEL, "1" );
		return 1;
	}
	//logMessage( LOG_INFO_LEVEL, "2.5" );
	//MagicValue_start
	if (*(uint32_t*)packet != SG_MAGIC_VALUE)
	{
		//logMessage( LOG_INFO_LEVEL, "3" );
		return 1;
	}
	//MagicValue_end
    if(*(uint32_t*)(packet+plen-sizeof(uint32_t))!=SG_MAGIC_VALUE)
    {
		//logMessage( LOG_INFO_LEVEL, "4");
        return 1;
    }
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : deserialize_sg_packet
// Description  : De-serialize a ScatterGather packet (unpack packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - UNIT_TEST_NUM the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status deserialize_sg_packet( SG_Node_ID *loc, SG_Node_ID *rem, SG_Block_ID *blk, 
        SG_System_OP *op, SG_SeqNum *sseq, SG_SeqNum *rseq, char *data, 
        char *packet, size_t plen ) {
	//if (packet==NULL)
	//{
		//logMessage( LOG_INFO_LEVEL, "1" );
	//	return SG_PACKT_PDATA_BAD;
	//}
	//if(plen==0)
	//{
		//logMessage( LOG_INFO_LEVEL, "2" );
		//return SG_PACKT_PDATA_BAD;
	//}
	if (checkPacket(packet,plen))
	{
		return SG_PACKT_PDATA_BAD;
	}
	SG_Packet_Info* packInfo = (SG_Packet_Info*)(packet+sizeof(uint32_t));
    *loc = packInfo->locNodeId;
	*rem = packInfo->remNodeId;
	*blk = packInfo->blockID;
	*op = packInfo->operation;
	*sseq = packInfo->sendSeqNo;
	*rseq = packInfo->recvSeqNo;
    
	memcpy(data,packet+sizeof(uint32_t)+sizeof(SG_Packet_Info),plen - sizeof(uint32_t)*2-sizeof(SG_Packet_Info));
	
	return SG_PACKT_OK;
}
        

//isSerialize: 1:serialize 0:deserialize
void PrintPacketStatusInfo(SG_Packet_Status status,int isSerialize)
{
	switch (status)
		{
		case SG_PACKT_OK:
		{
			logMessage( LOG_INFO_LEVEL, "sg_packet proccessing worked correctly (single packet)." );
		}
		break;
		case SG_PACKT_LOCID_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad local ID [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad local ID [0]." );
		}
		break;
		case SG_PACKT_REMID_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad remote ID [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad remote ID [0]." );
		}
		break;
		case SG_PACKT_BLKID_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad block ID [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad block ID [0]." );
		}
		break;
		case SG_PACKT_OPERN_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad op code (212)." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad op code (212)." );
		}
		break;
		case SG_PACKT_SNDSQ_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad sender sequence number [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad sender sequence number [0]." );
		}
		break;
		case SG_PACKT_RCVSQ_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad receiver sequence number [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad receiver sequence number [0]." );
		}
		break;
		case SG_PACKT_BLKDT_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad block data [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad block data [0]." );
        }
		break;
		case SG_PACKT_BLKLN_BAD:
		{
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad block length [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad block length [0]." );
		}
		break;
        case SG_PACKT_PDATA_BAD:
        {
			isSerialize==1?
            logMessage( LOG_ERROR_LEVEL, "serialize_sg_packet: bad packet data [0]." ):
			logMessage( LOG_ERROR_LEVEL, "deserialize_sg_packet: bad packet data [0]." );
        }
        break;

		}
}

int packetUnitTest(void)
{
	srand(time(NULL));

	for (int i=0;i<UNIT_TEST_NUM;++i)
	{
		SG_Node_ID loc = rand()%20;
		SG_Node_ID rem = rand() % 20;
		SG_Block_ID blk = rand() % 10;
		SG_System_OP op = rand() % 7;
		SG_SeqNum sseq = rand() % 20;
		SG_SeqNum rseq = rand() % 20;
		char *data=NULL;
		char *packet=(char*)malloc(SG_DATA_PACKET_SIZE);
		size_t plen=0;
		
		if (loc<18)
		{
			data = (char*)malloc(5);
			data[0] = 'd';
			data[1] = 'a';
			data[2] = 't';
			data[3] = 'a';
			data[4] = '\0';
		}

        SG_Packet_Status status= serialize_sg_packet(loc,rem,blk,op,sseq,rseq,data,packet,&plen);
		PrintPacketStatusInfo(status,1);

		free(data);
		data=(char*)malloc(plen - sizeof(uint32_t)*2-sizeof(SG_Packet_Info));

		//char* infoPtr = packet + sizeof(uint32_t)+sizeof(SG_Packet_Info);
		if(status==SG_PACKT_OK)
		{
			//logMessage( LOG_INFO_LEVEL, "test");
			//logMessage( LOG_INFO_LEVEL, infoPtr);
			//1.dlogMessage( LOG_INFO_LEVEL, *(((SG_Packet_Info*)infoPtr)->data));
			//logMessage( LOG_INFO_LEVEL, "test\n\n");
		}
		status= deserialize_sg_packet(&loc,&rem,&blk,&op,&sseq,&rseq,data,packet,plen);
		PrintPacketStatusInfo(status,0);

		if (data!=NULL)
		{
			free(data);
		}
		if (packet!=NULL)
		{
			free(packet);
		}
		
		
		
	}

    return 0;
}   
