/*
 * Ryan Foster
 * RF19L
 * 11/24/2021
 * CEN 4020
 * Dr. Gaitros
 */

/*
 *  PROJECT DESCRIPTION
 *
 *  Implements simplified IDEA algorithm according to Assignment 4 instructions.
 *  Accepts plain text input between 16 and 256 characters
 *  Accepts 32 character string of 1's and 0's for the key
 *  Outputs a hex representation of encrypted cipher text
 *
 *
 *  Project Flow:
 *  1. Get input from user, verify it is correct length.
 *  2. If input length is not a multiple of 16 pad with /0
 *  3. Keys are generated, and stored in a 5 by 6 vector, where each row corresponds to a round in encryption
 *  4. The "subroutine" function is then called on each subsection of the plaintext input.
 *  4a. Each 16 char word is separted into 4 char substrings
 *  4b. Each substring is converted from ascii value to a string representation of the binary value
 *  4c. Each binary string is converted to an unsigned integer.
 *  5.  Each 16 bit string in unsigned integer format is passed to the encryption algorithm
 *  6. Subroutine oututs an encrypted hex value
 *  7. Hex values are concatenated in main and output
 *  8. End of program
 *
 *
 */

#include <iostream>
#include <vector>
#include <bitset>

// Perform rounds 1 through 4 of the routine.   The int round number tells the routine which
// keys to use.
unsigned int Rounds1thru4(std::vector<unsigned int>& words, const unsigned int round,const std::vector<unsigned int> keys);

// Performs round 5 of the routine. Again, the round number tells it which set of keys to use.
unsigned int Round5(std::vector<unsigned int>& words, const unsigned int round,const std::vector<unsigned int> keys);

// Remember we are only dealing with 4 bit items.   So the following routine is very short.
// There are 8 four bit parts to a word so this routine does is extracts the 4 bits and returns it
// value.   Let's say that I have a hex value 00F1CA10 and I said I wanted key number 3, it would return
//  0000000A
unsigned int ReturnKey(const unsigned int word, const unsigned int key);

// I gave this one to you.
unsigned int CircularShift(const unsigned int word, const unsigned int shiftamt);

// Performs the modular multiply between two words.
unsigned int ModuloMult(const unsigned int word1,const unsigned int word2);

// Performs the ModuloAdd between two words.
unsigned int ModuloAdd (const unsigned int word1,const unsigned int word2);

// Performs the ModuloAdd between two words.
unsigned int ModuloXor (const unsigned int word1,const unsigned int word2);

void addToVector(std::vector<unsigned int> subkeys, std::vector<unsigned int>& original);

std::vector<unsigned int> BinStringToUint(std::vector<std::string> input);


std::vector<unsigned int> generateSubKeys(unsigned int key);

std::string toBinaryString(std::string& word);

void StringPad(std::string& input);

std::string subRoutine(std::string word, const std::vector<std::vector<unsigned int>>& keys);

std::vector<std::string> AsciiToBinString(std::vector<std::string> input);

const unsigned int MODULO_AMOUNT = 16;


int main() {
    /*
     * Get Input Plain Text
     */
    std::string inputStringTest = "\t\f\n\f"; //TODO remove test value

    //std::string inputStringTest="I hate this class."; //TODO Delete this, used to compare w/ cole and mikes results

    /* //TODO UNCOMMENT TO TAKE CONSOLE INPUT
    while(inputStringTest.length()<16 || inputStringTest.length()>256){
        fprintf(stderr,"String must be between 16 and 256 characters\n");
        std::getline(std::cin,inputStringTest);
    }
     */

    StringPad(inputStringTest);
    unsigned int n_substrings = inputStringTest.length() / 16;
    fprintf(stderr,"DEBUG: \nPadded Len:%lu\n",inputStringTest.length());
    fprintf(stderr,"DEBUG: \nNumber of Substrings:%d\n",n_substrings);

    /*
     * Get each 16 character sequence
     */
    std::vector<std::string> substrings;
    for(int i =0; i < n_substrings;i++){
        std::string temp;
        for(int j=16*i;j<=inputStringTest.length();j++){
            temp+=inputStringTest[j];
            if(temp.length()==16){
                substrings.push_back(temp);
            }
        }
    }


    /*
     * Get key input
     */
    std::vector<unsigned int> subkeys;
    std::string testkeyInput= "11011100011011110011111101011001"; //TODO remove default values
    //std::string testkeyInput="00100101110011110100101110100111"; //TODO REMOVE COLE TEST CASE

    while(testkeyInput.length() != 32){
        std::getline(std::cin,testkeyInput);
    }

    /*
     * Verify only 1's and 0's were entered for the key
     */
    for(auto& c: testkeyInput){
        if(c!= '0' && c!='1'){
            fprintf(stderr,"ERROR\n Key must be exactly 32 characters consisting of only 1's and 0's");
            exit(-1);
        }
    }

    /*
     * Convert key to unsigned int
     */
    unsigned long lkey = strtoul(testkeyInput.c_str(),NULL,2);
    unsigned int key = lkey;
    fprintf(stderr,"DEBUG:\n Key Decimal Value:%d",key);

    /*
     * Generate Keys
     */
    for(int i =0;i<4;i++){
        std::vector<unsigned int> temp_keys = generateSubKeys(key);
        addToVector(temp_keys,subkeys);
        //shift bits and continue
        key = CircularShift(key,6);
        temp_keys.clear();
    }

    /*
     * Convert to a 5 by 6 vector
     */
    std::vector<std::vector<unsigned int>> final_keys;
    int count =0;
    int index =0;
    std::vector<unsigned int> temp;
    for(const auto& i : subkeys){
       // final_keys.at(index).push_back(i);
       temp.push_back(i);
        count +=1;
        if(count % 6 == 0){
            final_keys.push_back(temp);
            temp.clear();
            index+=1;
        }
    }

    /*
    * Empty key building vector
    */
    if(!temp.empty()){
        final_keys.push_back(temp);
        temp.clear();
    }


    /*
     * DEBUG - Print All Keys
     */
    for(int i=0;i<final_keys.size();i++){
        fprintf(stderr,"\nRound %d:\n",i);
        int counter =1;
        for(auto& j : final_keys.at(i)){
            fprintf(stderr,"%d:%x\t",counter, j);
            counter+=1;
        }
    }


    /*
     * Call subroutine on each 16 character sequence
     */
    std::string output;
    for(int i=0;i<n_substrings;i++){
        output += subRoutine(substrings[i],final_keys);
    }

    /*
     * Convert concatenated hex string to binary integer
     */
    unsigned long lconversion = strtoul(output.c_str(),NULL,16);
 //   unsigned int binoutput = lconversion;

    //fprintf(stdout,"\nCipherText:\t%s",output.c_str());
    fprintf(stdout,"\nCipherText:\t%lx",lconversion);



    return 0;
}

/*
 * Called for each 16 character sequence of the input
 *
 * Performs each 5 rounds on each 16 character portion.
 *
 * Returns a 4 digit hex value for each time it's called
 */
std::string subRoutine(std::string word, const std::vector<std::vector<unsigned int>>& keys) {
    std::vector<std::string> substrings;
    std::string stringbuilder;

    /*
     * Separate into 4 substrings
     */
    for(int i =0; i<16;i++) {
        stringbuilder+=word[i];
        if(stringbuilder.length() ==4){
            substrings.push_back(stringbuilder);
            stringbuilder.clear();
        }
    }

    /*
     * Convert each substring to binary
     */
    std::vector<std::string> binStrings = AsciiToBinString(substrings);
    std::vector<unsigned int> binaryVector= BinStringToUint(binStrings);
   // std::string testing_function = toBinaryString(word);

    /*
     * First Four Rounds
     */
    for(int i = 0; i <4;i++){
        Rounds1thru4(binaryVector,i,keys.at(i));
    }
    /*
     * Final Round
     */
    Round5(binaryVector,4,keys.at(4));

    /*
     * Convert each nibble to a hex char and return the word
     */
    char hex_string[4];
    std::string mytemp;
    for(unsigned int binString : binaryVector){
        sprintf(hex_string,"%X",binString);
        mytemp+=hex_string;
    }

    /*
     * Return 4 digit hex value
     */
    return mytemp;

}

/* CircularShift - Takes a single word and shifts the bits to the   *
// * left the number of bits indicated by the shift amt parameter, and*
// * taking the left-hand bits and appending them to the right most   *
 side.                                                            *
*/
unsigned int CircularShift(const unsigned int word, const unsigned int shiftamt)
{
    unsigned int mask = 1;       // Create a mask bit
    unsigned int result=0;       // Result of or operation
    unsigned int returnresult;   // The answer we send back
    mask=mask<<31;               // Set the bit to the left
    returnresult = word;
    for (int index=0; index<shiftamt; index++)
    {
        result = returnresult & mask;           // Get the left most bit
        if(result!=0) result=1;
        else result=0;
        returnresult= returnresult<<1;          // Shift the word left 1 bit
        returnresult = returnresult| result;    // Put the bit on the right
    }

    return returnresult;

}

unsigned int ModuloMult(const unsigned int word1, const unsigned int word2) {
    unsigned int val1 = word1,val2=word2;
    unsigned int total;
    if (val1 % MODULO_AMOUNT == 0) val1=MODULO_AMOUNT;
    if (val2 % MODULO_AMOUNT == 0) val2=MODULO_AMOUNT;
    total = val1*val2;

    while(total >= MODULO_AMOUNT){
        total -= (MODULO_AMOUNT+1);
    }
    return total;
}

unsigned int ModuloAdd(const unsigned int word1, const unsigned int word2) {
    unsigned int total = word1+word2;

    while (total >= 16){
        total -= 16;
    }
    return total;
}

unsigned int ModuloXor(const unsigned int word1, const unsigned int word2) {
    unsigned int total;
    total = word1^word2;
    return total & 0xF;
}

/*
 * Gets each nibble from a 32 bit binary from left to right
 */
std::vector<unsigned int> generateSubKeys(unsigned int key) {
    fprintf(stderr,"DEBUG:\n Original Key:%x",key);
    std::vector<unsigned int> nibbles;
    unsigned int signifigant_bits = 0xF0000000;
    for(int i =0;i<8;i++){
        fprintf(stderr,"\nKey: %x \t Leftmost Bits: %x \n",key,signifigant_bits);

        unsigned int bits = key & signifigant_bits;
        bits = bits>>28;
       // fprintf(stderr,"DEBUG:\n%x, %d\n",bits,bits);
        key = key << 4;
        fprintf(stderr,"DEBUG:\nAfter Shift\n Key: %x \t LeftMost Bits: %x \n\n",key,signifigant_bits);
        nibbles.push_back(bits);

        if(bits > 0xF){
            fprintf(stderr,"Out of range error, nibble too large");
            exit(-1);
        }
    }


    return nibbles;
}

/*
 * Convert ascii input to unsigned integer
 */
std::vector<unsigned int> BinStringToUint(std::vector<std::string> input) {
    std::vector<unsigned int> binVector;

    /*
     * Get ascii value for each char
     */

    for(const auto& i : input){
        unsigned long lkey = strtoul(i.c_str(),NULL,2);
        unsigned int key = lkey;
        binVector.push_back(key);
        }

    return binVector;
}

/*
 * append one vector to the end of another vector
 */
void addToVector(std::vector<unsigned int> subkeys, std::vector<unsigned int>& original){
    for(int i =0; i<8;i++){
        original.push_back(subkeys.at(i));
        if(original.size() >= 28){
            break;
        }
    }
}

/*
 * Pad each string that is not length 16, with null characters
 */
void StringPad(std::string& input){
    if(input.length() == 16){
        return;
    }
    char pad_char = '\0';
    unsigned int temp = input.length() % 16;
    unsigned int padding = 16-temp;
    for(int i =0; i<padding;i++){
        input += pad_char;
    }

}

unsigned int Rounds1thru4(std::vector<unsigned int>& words, const unsigned int round, const std::vector<unsigned int> keys) {
    unsigned int one = ModuloMult(words.at(0),keys.at(0));
    unsigned int two = ModuloAdd(words.at(1),keys.at(1));
    unsigned int three = ModuloAdd(words.at(2),keys.at(2));
    unsigned int four = ModuloMult(words.at(3),keys.at(3));
    unsigned int five = ModuloXor(one,three);
    unsigned int six = ModuloXor(two,four);
    unsigned int seven = ModuloMult(five,keys.at(4));
    unsigned int eight = ModuloAdd(six,seven);
    unsigned int nine = ModuloMult(eight,keys.at(5));
    unsigned int ten = ModuloAdd(seven,nine);
    unsigned int eleven = ModuloXor(one,nine);
    unsigned int twelve = ModuloXor(three,nine);
    unsigned int thirteen = ModuloXor(two,ten);
    unsigned int fourteen = ModuloXor(four,ten);

    words.at(0) = eleven;
    words.at(1) = thirteen;
    words.at(2) = twelve;
    words.at(3) = fourteen;

    return 0;
}

unsigned int Round5(std::vector<unsigned int> &words, const unsigned int round, const std::vector<unsigned int> keys) {
    unsigned int one = ModuloMult(words.at(0),keys.at(0));
    unsigned int two = ModuloAdd(words.at(1),keys.at(1));
    unsigned int three = ModuloAdd(words.at(2),keys.at(2));
    unsigned int four = ModuloMult(words.at(3),keys.at(3));
    words.at(0)=one;
    words.at(1)=two;
    words.at(2)=three;
    words.at(3)=four;
    return 0;
}

std::string toBinaryString(std::string &word) {
    std::string s;
    for(char i : word){
        unsigned int temp = (int)i;
        s += std::to_string(temp);
    }
    return s;
}

std::vector<std::string> AsciiToBinString(std::vector<std::string> input) {
    std::vector<std::string> binStrings;
  //  char bin_string[8];
    std::string mytemp;
    for(auto& i: input){
        for(auto& j: i){
            unsigned int temp = '\0'+j;
            std::bitset<8> bits(temp);
          //  fprintf(stderr,"\nBits For %c:\t%s\n",j,bits.to_string().c_str());
            binStrings.push_back(bits.to_string());
        }
    }
    return binStrings;
}
