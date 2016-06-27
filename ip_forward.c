/*

  Kendall Weihe
  Dr. Zongming Fei
  CS 371 Spring 2016
  Program:
    Inputs: argv[1] = binary ip_packet file, argv[2] = routing_table.txt file
    Outputs: header field values, checksum verification, TTL verification, NextHop IP address
    This is a simplistic version of an IP forwarding program that routers use
      to forward IP packets. General pseudocode can be found above to main program.
    For detailed description of program, please see README.txt.
    I have verified writing to the output file by making ip_packet_out and input to the program
      and verifying all headers are equivalent
*/

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#define MAXSIZE 512

/*

  In host form:
   ________________________________________________
  |lowest order|         |          | highest order|
   ------------------------------------------------

   In network form:
    ________________________________________________
   |highest order|         |          | lowest order|
    ------------------------------------------------

    chars are equivalent across both byte orders, but everything else needs conversions

*/


struct line_type_1 { //for header lines of type 1 (version, header length, datagram length, TTL, protocol, checksum)
  unsigned char a;
  unsigned char b;
  unsigned short c;
};

struct line_type_2 { //for header lines of type 2 (identification, flag bits and fragmentation)
  unsigned short a;
  unsigned short b;
};

struct line_type_3 { //for header lines of type 3 (IP fields)
  unsigned long a;
};

struct line_type_1 l1;
struct line_type_2 l2;
struct line_type_1 l3;
struct line_type_3 l4;
struct line_type_3 l5;
char *routing[MAXSIZE][MAXSIZE]; //char string array to hold routing table identifiers
unsigned short overflow = 65535; //overflow value for calculating checksum
unsigned int number_of_net_ids = 0;

/*
  This function simply handles cases during checksum calculation where there is an overflow bit
*/
int handle_overflow(unsigned long checksum){
  checksum = checksum - overflow; //subtract 2^16 and add 1
  return checksum;
}


/*
  This function computes the checksum
    Sum all 16 bit fields & check for overflow bits then return ones complement
    The temporary variable must be of type unsigned long since values can exceed 2^16 - 1
    Each 16-bit block is of type unsigned short since they are 16-bits long
*/
int compute_checksum(unsigned short block1, unsigned short block2, unsigned short block3, unsigned short block4, unsigned short block5, unsigned short block6, unsigned short block7, unsigned short block8, unsigned short block9){
  unsigned long checksum_temp = block1 + block2;
  if (checksum_temp > overflow){
    checksum_temp = handle_overflow(checksum_temp); //call function to handle overflow
  }
  checksum_temp += block3;
  if (checksum_temp > overflow){
    checksum_temp = handle_overflow(checksum_temp);
  }
  checksum_temp += block4;
  if (checksum_temp > overflow){
    checksum_temp = handle_overflow(checksum_temp);
  }
  checksum_temp += block5;
  if (checksum_temp > overflow){
    checksum_temp = handle_overflow(checksum_temp);
  }
  checksum_temp += block6;
  if (checksum_temp > overflow){
    checksum_temp = handle_overflow(checksum_temp);
  }
  checksum_temp += block7;
  if (checksum_temp > overflow){
    checksum_temp = handle_overflow(checksum_temp);
  }
  checksum_temp += block8;
  if (checksum_temp > overflow){
  }
  checksum_temp += block9;
  if (checksum_temp > overflow){
    checksum_temp = handle_overflow(checksum_temp);
  }

  return ~checksum_temp;
}


/*
  This function finds the next hop for the destination IP and prints it to the terminal
    Logical & the destination IP address with the Mask value from the routing_table.txt
      If the results matches NetID then record line number in routing_table.txt
      If there are no matches, then the default match will be 0.0.0.0
      If multiple matches are found, then the longest preficx match is chosen
        There are only four length options 255.0.0.0., 255.255.0.0, 255.255.255.0, 255.255.255.255
*/
void find_next_hop(unsigned long dest_ip_address_int){
  unsigned int i, length_1 = 0, length_2 = 0, length_3 = 0, length_4 = 0, line_number, a,b,c,d;

  //loop through all lines in routing_table.txt
  for (i = 0; i < number_of_net_ids; i++){
    sscanf(routing[i][0], "%u.%u.%u.%u", &a, &b, &c, &d); //read in the dotted decimal values for the net_id
    unsigned long net_id = a * 16777216 + b * 65536 + c * 256 + d; //convert the values to unsigned long form
    sscanf(routing[i][1], "%u.%u.%u.%u", &a, &b, &c, &d); //read in the dotted decimal values for the mask
    unsigned long mask = a * 16777216 + b * 65536 + c * 256 + d; //convert the values to unsigned long form
    if (net_id == (dest_ip_address_int & mask)){ //perform logical & with the mask and check if equal to net_id
      if (b == 0 && length_2 == 0 && length_4 == 0 && length_3 == 0 && length_2){ //case 255.0.0.0
        //1st length
        length_1 = 1;
        line_number = i;
      }
      else if (b != 0 && c == 0 && length_4 == 0 && length_3 == 0){ //case 255.255.0.0
        //2nd length
        length_2 = 1;
        line_number = i;
      }
      else if (b != 0 && c != 0 && length_4 == 0){ //case 255.255.255.0
        //3rd length
        length_3 = 1;
        line_number = i;
      }
      else if (b != 0 && c != 0 && d != 0){ //case 255.255.255.255
        //4th length
        length_4 = 1;
        line_number = i;
      }
    }
    // printf("NetID = %s\n", routing[i][0]);
    // printf("Mask = %s\n", routing[i][1]);
  }
  if (line_number == 0){ //case where there were no matches
    //nexthop = 0.0.0.0
    line_number = 6;
    printf("no matches\n");
  }
  printf("Nexthop = %s\n", routing[line_number][2]); //print the next hop found from line_number variable
  printf("\n");
}


/*
  This function performs the bulk of the program
    - reads the binary ip_packets file into the correct structures (structure depends on the layout of the packet line)
    - prints out header info
    - stores each 16-bit block (for the checksum verification)
    - verifies checksum
      - if verified decrement TTL
      - else drop
    - verifies TTL is not equal to zero
    - computes new checksum after decrementing TTL
    - reads in the data field
    - calls find_next_hop function
    - writes packets that pass both verifications to an output file
*/
void handle_ip_packets(FILE *ip_packets, FILE *ip_packet_out){
  unsigned short block1, block2, block3, block4, block5, block6, block7, block8, block9;

  fread(&l1, 4, 1, ip_packets); //read in first line
  if (feof(ip_packets)) //if the end of file has been detected, then return to main()
    return;
  unsigned int version; //version is the first 4-bits of the field
  version = l1.a & 0xf0; //extract version field
  version = version >> 4;
  printf("Version = %u\n", version);
  unsigned char header_length; //header length is the second 4-bit field
  header_length = l1.a & 0x0f; //extract header length
  header_length *= 4;
  printf("Header length = %u\n", header_length);
  unsigned char type_of_service = l1.b; //type of service is the 2nd byte of the line
  printf("Type of service = %u\n", type_of_service);
  unsigned short datagram_length = ntohs(l1.c); //datagrame length is the third and fourth byte -- since it is an unsigned short, it must be converted to host byte order
  printf("Datagram length = %u\n", datagram_length);
  block1 = ntohs((l1.a << 8) + l1.b); //store the first 16-bit block
  block2 = l1.c; //store the second 16-bit block

  fread(&l2, 4, 1, ip_packets); //read second line
  unsigned short identifier = ntohs(l2.a); //identifier is the first 16-bit field -- convert to host byte order
  printf("Identifier = %hu\n", identifier);
  unsigned short flags_and_offset = ntohs(l2.b); //flags and offset value makes up the second 16-bit field -- convert order
  printf("Flag & offset = %hu\n", flags_and_offset);
  block3 = (l2.a); //store third 16-bit field
  block4 = (l2.b); //store fourth 16-bit field

  fread(&l3, 4, 1, ip_packets); //read third line
  char ttl = l3.a; //TTL is the first byte field
  printf("TTL = %u\n", ttl);
  char protocol = l3.b; //protocol identifier is the second byte field
  printf("Protocol = %u\n", protocol);
  unsigned short checksum = (l3.c); //checksum is the third and fourth byte fields -- don't convert for later checksum calculation
  printf("Checksum = %hu\n", ntohs(checksum)); //convert when printing
  block5 = ntohs((l3.a << 8) + l3.b); //store fifth 16-bit field
  //include checksum

  fread(&l4, 4, 1, ip_packets); //read fourth line
  struct in_addr ip_addr; //store 32-bit IP address in the in_addr struct so that we can convert to dotted decimal
  ip_addr.s_addr = l4.a;
  char *src_ip_address = inet_ntoa(ip_addr); //convert to dotted decimal form
  printf("The source IP address = %s\n", src_ip_address);
  unsigned long src_ip_host_order = inet_addr(inet_ntoa(ip_addr)); //convert to host order
  printf("The source IP address in host order = %lu\n", src_ip_host_order);
  block6 = (l4.a >> 16); //store 6th 16-bit field
  block7 = (l4.a & 0x0000ffff); //store 7th 16-bit field

  fread(&l5, 4, 1, ip_packets); //read fifth line
  ip_addr.s_addr = l5.a; //store 32-bit IP address in in_addr struct so that we can show in dotted decimal form
  char *dest_ip_address = inet_ntoa(ip_addr); //use inet_ntoa() function to convert to dotted decimal
  printf("The destination IP address = %s\n", dest_ip_address);
  unsigned long dest_ip_host_order = inet_addr(inet_ntoa(ip_addr)); //convert to host order
  printf("The destination IP address in host order = %lu\n", dest_ip_host_order);
  unsigned int a,b,c,d;
  sscanf(dest_ip_address, "%u.%u.%u.%u", &a, &b, &c, &d); //read in dotted decimal values
  unsigned long dest_ip_address_int =  a * 16777216 + b * 65536 + c * 256 + d; //convert to host ordering
  block8 = (l5.a >> 16); //store eigth 16-bit field
  block9 = (l5.a & 0x0000ffff); //store 9th 16-bit field

  //call compute_checksum to verify checksum
  unsigned short verify_checksum = compute_checksum(block1, block2, block3, block4, block5, block6, block7, block8, block9);
  // printf("%hu\n", verify_checksum);

  int checksum_flag = 0, ttl_flag = 0; //flags for verification
  if ((checksum - verify_checksum) != 0){ //case checksum fails, drop packet
    printf("Checksum fails, drop packet\n");
  }
  else{ //case checksum passes
    printf("Checksum verified, decrement TTL\n");
    ttl--;
    if (ttl == 0){ //case TTL has reached 0, so should be dropped
      ttl_flag = 1; //set flag to true
      printf("TTL has reached 0, drop packet\n");
    }
    block5 = ntohs((ttl << 8) + l3.b); //updated block5 TTL with new decremented value
    //computer new checksum
    checksum = compute_checksum(block1, block2, block3, block4, block5, block6, block7, block8, block9);
    checksum_flag = 1; //set flag to true
  }

  //read in data
  char *data[MAXSIZE];
  fread(&data, datagram_length - header_length, 1, ip_packets);

  //call find_next_hop and write to output packet
  if (ttl > 0 && checksum_flag == 1 && ttl_flag == 0){
    find_next_hop(dest_ip_address_int);
    fwrite(&block1, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block2, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block3, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block4, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block5, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&checksum, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block7, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block6, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block9, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&block8, sizeof(unsigned short), 1, ip_packet_out);
    fwrite(&data, datagram_length - header_length, 1, ip_packet_out);
  }
  else
    printf("\n");

}


/*
  This function inputs the routing_table.txt values into *routing[MAXSIZE][MAXSIZE] array
    Scan through each line and then input token into *routing array
      int token_count variable determines which column
      int line_count determines which line
*/
void input_routing_table(FILE *routing_table){

  char line[MAXSIZE], temp[MAXSIZE];
  int i = 0, j = 0, token_count = 0, line_count = 0;
  while(fgets(line, sizeof(line), routing_table) != NULL){
    number_of_net_ids++; //count the number of lines -- later used in finding next hop
    token_count = 0; //token count is which column is the current position
    for (i = 0; i < strlen(line); i++){
      memset(&temp[0], 0, sizeof(temp)); //clear the temp array
      if (line[i] != ' ' && token_count == 2){ //case third column
        for (j = 0; j < MAXSIZE; j++){ //loop through IP value
          if (line[i+j] == ' ') //case where it has reached the end of the IP
            break;
          temp[j] = line[i+j]; //add value to temp array
        }
        i += j; //update i value to end of IP value
        routing[line_count][token_count] = strdup(temp); //since routing is a pointer, duplicate temp to new address space
        token_count++; //update token count
      }
      else if (line[i] != ' ' && token_count == 1){ //case second column
        for (j = 0; j < MAXSIZE; j++){
          if (line[i+j] == ' ') //case reaced end of IP value
            break;
          temp[j] = line[i+j]; //input IP value to temp array
        }
        i += j; //update i value to end of IP value
        routing[line_count][token_count] = strdup(temp); //since routing is a pointer, duplicate temp to new address space
        token_count++;
      }
      else if (line[i] != ' ' && token_count == 0){ //case first column
        for (j = 0; j < MAXSIZE; j++){
          if (line[i+j] == ' ') //case reached end of IP value
            break;
          temp[j] = line[i+j]; //add IP value to temp array
        }
        i += j; //update i value to end of IP value
        routing[line_count][token_count] = strdup(temp); //since routing is a pointer, duplicate temp to new address space
        token_count++;
      }
    }
    line_count++; //line number used for *routing array
  }

  // //print the routing table
  // for (i = 0; i < line_count; i++){
  //   for (j = 0; j < 3; j++){
  //     printf("%s\n", routing[i][j]);
  //   }
  // }

}

/*
  Psuedocode:
    read first packet
    print header values
    validate checksum
      if != then drop
    validate TTL
      if ==1 then drop
    store header values
    scan through NetID's and Masks
    find longest prefix match
    print nexthop
    append packet to ip_packets_out
    repeat for all packets -- until EOF is reached
*/
int main(int argc, char* argv[]){

  FILE *ip_packets, *routing_table, *ip_packet_out;
  ip_packets = fopen(argv[1], "rb"); //open input binary IP packets file in read binary mode
  routing_table = fopen(argv[2], "r"); //open in routing table text file in read mode
  ip_packet_out = fopen("ip_packet_out", "ab"); //open binary IP output file in append binary mode

  input_routing_table(routing_table); //input the routing table to *routing array

  while(!feof(ip_packets)){ //loop until EOF -- each loop is a packet (file pointer updated in handle_ip_packets function)

    handle_ip_packets(ip_packets, ip_packet_out); //call function to handle IP packets

  }

  //close files
  fclose(ip_packets);
  fclose(routing_table);
  fclose(ip_packet_out);

}
