#include<bits/stdc++.h>
#include "sha256.h"

using namespace std;

//beginning of the sha256 functions' definitions
const unsigned int SHA256::sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
 
void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}
 
void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}
 
void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}
 
void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}
 
std::string sha256(std::string input)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);
 
    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);
 
    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return std::string(buf);
}

// sha256 functions end here

//number of transactions within a block
int numtrans=4;

// the map stores the stakes of every unique ID registered 
map<int, int> idStakes;

// the map stores the land ID each individual holds in the system
map<int, vector<int>> id_lands;

//vector contains hash of each transaction
vector<string> transHash;

//voting to find the top delegates through the process of voting
vector<pair<int, int>> voting(){
    vector<pair<int, int>> votes(idStakes.size());

    for(int i=0; i<idStakes.size(); i++){
        votes[i]={idStakes[i]*(rand()%100), i};
    }

    sort(votes.begin(), votes.end(), greater<>());
    return votes;
}

//Transaction class to the details essential to carry out the transaction
class Transaction {
    public:
    int buyerID;
    int sellerID;
    int landID;
    string transhash;
    time_t tTime;

    //default constructor
    Transaction();

    //function to calculate the hash of each transaction
    string CalculateTransHash() const;
};

//defining the constructor of transaction class
Transaction::Transaction(){
    buyerID=0;
    sellerID=0;
    landID=0;
    tTime= time(nullptr);
    transhash=CalculateTransHash();
}

//hashing the transaction using SHA256
inline string Transaction::CalculateTransHash() const
{
    stringstream ss;
    ss << buyerID << sellerID << landID << tTime;

    return sha256(ss.str());
}

//Function to print all the transaction history related to a particular land
void TransactionHistory(int ID,vector<Transaction> &allTrans){
    cout<<allTrans.size();
  for(int i=0;i<allTrans.size();i++)
  {
    if(allTrans[i].landID==ID)
    {
        cout<<"This land was successfully sold by "<<allTrans[i].sellerID<<" to "<<allTrans[i].buyerID;
    }
  }
  return;
}

//Node class as a basic unit of the merkle tree
class Node {
    public:
    string hash;
    Node *left;
    Node *right;

    Node(string data);
};

Node::Node(string data) {
    hash = data;
}

// Function to assign stakes through a random function
// to the unique identity in the system
// after each transaction is being carried
void assignStakes(vector<Transaction>& allTrans, int idx)
{
    if(idStakes.find(idx)==idStakes.end())
    {
        idStakes[idx]=rand()%100;
    }
}
//Defining our block as class
//each block contains the merkle root of transactions 
//the hash of the previous block and a NONCE
class Block {
public:
    string sHash;
    string sPrevHash;
    string rootHash;
    Block();
    Block(uint32_t nIndexIn, Transaction ipdata1, Transaction ipdata2, Transaction ipdata3, Transaction ipdata4);

    void MineBlock();
    string giveRoot();

private:
    uint32_t nIndex;
    uint32_t nNonce;
    Transaction trans1; 
    Transaction trans2; 
    Transaction trans3; 
    Transaction trans4;

    string CalculateHash() const;
};

//default block constructor
Block::Block()
{
    nIndex=0;   
    
    nNonce = 0;
    sHash = CalculateHash();
    //cout<<"yes";
    rootHash=giveRoot();
    
}


Block::Block(uint32_t nIndexIn, Transaction ipdata1, Transaction ipdata2, Transaction ipdata3, Transaction ipdata4)
{
    nIndex=nIndexIn;
    trans1=ipdata1;
    trans2=ipdata2;
    trans3=ipdata3;
    trans4=ipdata4;   
    
    nNonce = 0;
    rootHash=giveRoot();
    
}

//Function returns the merkle root obtained after 
//consecutive binary hashing of all the transactions within a block
string Block::giveRoot() {
    vector<Node*> nodes;
    int counter=numtrans;
    int c=1;
    while(counter--){
        auto it=transHash.end();

        Node* newNode= new Node(*(it-c));
        nodes.push_back(newNode);
        c++;
    }
    vector<Node*> hashednodes;
    
    while (nodes.size() != 1) 
    {
        for (unsigned int l = 0, n = 0; l < nodes.size(); l = l + 2, n++) 
        {
            if (l != nodes.size() - 1) 
            {
                Node* temp=new Node(sha256(nodes[l]->hash + nodes[l+1]->hash)); // checks for adjacent block
                hashednodes.push_back(temp); // combine and hash adjacent blocks
                hashednodes[n]->left = nodes[l]; // assign children
                hashednodes[n]->right = nodes[l+1];
            } 
            else
            {
                hashednodes.push_back(nodes[l]);
            }
        }
        nodes = hashednodes;
        hashednodes.clear();
    }
    return nodes[0]->hash;
}

// function calculates hash of the block
// includes the merkle root of transactions
// header details of current block and
// hash obtained from the header of previous block 
inline string Block::CalculateHash() const
{
    stringstream ss;
    ss << nIndex << sPrevHash << trans1.tTime << trans1.buyerID << trans1.sellerID << trans2.tTime << trans2.buyerID << trans2.sellerID <<trans3.tTime << trans3.buyerID << trans3.sellerID<< nNonce;

    return sha256(ss.str());
}


// function carries out the task of mining the block
// after the predecided number of transactions have been made
// mining of blocks is done by the delegates chosen after voting 
void Block::MineBlock()
{
    vector<pair<int, int>> votes=voting();

    string str1=to_string(votes[0].second);
    string str2=to_string(votes[1].second);
    string str3=to_string(votes[2].second);
    int n1=str1.length();
    int n2=str2.length();
    int n3=str3.length();
    cout<<"The selected delegates: "<<str1<<" "<<str2<<" "<<str3<<"\n";
    do
    {
        nNonce++;
        sHash = CalculateHash();
    }
    while (sHash.substr(0,n1) != str1 );

    cout << "Block mined: " << sHash << endl;
}

class Blockchain {
public:
    Blockchain();

    void AddBlock(Block bNew);

    vector<Block> vChain;

private:
    Block GetLastBlock() const;
};

// default constructor of blockchain class
Blockchain::Blockchain()
{
    vChain.push_back(Block());
}

// returns the address of the last block in the blockchain
Block Blockchain::GetLastBlock() const
{
    return vChain.back();
}

// adds a new block at the end of the blockchain 
void Blockchain::AddBlock(Block bNew)
{
    bNew.sPrevHash = GetLastBlock().sHash;
    bNew.MineBlock();
    vChain.push_back(bNew);
}

// function carries out the process of a transaction
// transfers land from the name of the seller to name of the buyer 
// stores all the transactions to return data pertaining to a specific land if required
void transferLand(vector<Transaction> &allTrans){
    Transaction dummy;
        cout<<"Please enter the unique Buyer ID\n";
        cin >> dummy.buyerID;
        cout<<"Please enter the unique Seller ID\n";  
        cin>> dummy.sellerID ;
        cout<<"Please enter the unique Land ID\n"; 
        cin>> dummy.landID;
        cout<<allTrans.size();

        transHash.push_back(dummy.transhash);
        assignStakes(allTrans,dummy.sellerID);
        assignStakes(allTrans,dummy.buyerID);
        if(find(id_lands[dummy.sellerID].begin(),id_lands[dummy.sellerID].end(),dummy.landID)==id_lands[dummy.sellerID].end())
        {
            cout<< "The seller does not hold any land yet\n\n";
        }
        else
        {
            
            allTrans.push_back(dummy);
            
            for(int i=0;i<id_lands[dummy.sellerID].size();i++)
            {
                
                if(id_lands[dummy.sellerID][i]==dummy.landID)
                {
                    
                    auto it=find(id_lands[dummy.sellerID].begin(), id_lands[dummy.sellerID].end(), dummy.landID)-id_lands[dummy.sellerID].begin();
                    
                    id_lands[dummy.sellerID].erase(it+id_lands[dummy.sellerID].begin());
                    cout << "The land " << dummy.landID << " has been transferred from " << dummy.sellerID << " to " << dummy.buyerID<<"\n\n";
                    break;
                }

            }
            id_lands[dummy.buyerID].push_back(dummy.landID);
            
        }
}

int main()
{
   transHash.push_back(sha256("RIYA"));
    transHash.push_back(sha256("AFRIN"));
    transHash.push_back(sha256("SANSKAR"));
    transHash.push_back(sha256("ISHIKA")); 
    
    // declaring a new blockchain
    Blockchain bChain;

    // array of class "transaction" to hold al the transactions occured
    vector<Transaction> allTrans;
    int userIP, transCount=0;//user input choice and total number of transactions that have taken place till now
    
    auto lastPointer=allTrans.end();//returns pointer to the end of alltrans array

    //user input choices
    cout << "1. Register as Seller"<<"\n"<<"2. Makes a Transaction\n3. View Transaction History of a land\n4. Exit\n";
    cin >> userIP;

    while(userIP!=4)//user does not want to exit
    {
        if(userIP==1)// if the user wants to register himself on the land management portal
        {
            int seller,land;
            cout<<"Enter Your Unique Seller Number and The Land you Own\n";
            cin>>seller>>land;
            id_lands[seller].push_back(land);

            assignStakes(allTrans, seller);

        }
        else if(userIP==2)// if the user want to carry out a transaction,i.e.,transfer of a land
        {
            if(userIP==2 && transCount!=0 && transCount%4==0)
            {
                cout << "Mining block " << transCount/3 << "..." << endl;
                auto lastPointer=allTrans.end();
                bChain.AddBlock(Block(transCount/4, *(lastPointer-1), *(lastPointer-2), *(lastPointer-3), *(lastPointer-4)));
                
                transferLand(allTrans);

                assignStakes(allTrans, transCount);
                transCount++;
            }
            else if(userIP==2)
            {
                transferLand(allTrans);
                assignStakes(allTrans, transCount);
                transCount++;
            }

        }
        else if(userIP==3)// if the user wants to review the transactions carried out in the past on a particular land
        {
                int id=0;
                cout<<"Enter the Land ID whose details are to be viewed: \n";
                cin>>id;
                TransactionHistory(id,allTrans);
   
                
        }
        if(transCount!=0 && transCount%4==0)
        continue;
        cout << "1. Register as Seller"<<"\n"<<"2. Makes a Transaction\n3. View Transaction History of a land\n4. Exit\n";
            cin >> userIP;

    }
    
    //if the user wants to exit before adding transactions enough for one block
    if(userIP==4 && transCount!=0 && transCount%4==0)
    {
        cout << "Mining block" << transCount/4 << "..." << endl;
        auto lastPointer=allTrans.end();
        bChain.AddBlock(Block(transCount/4, *(lastPointer-1), *(lastPointer-2), *(lastPointer-3), *(lastPointer-4)));
    }
    else{
        cout << "Need atleast 4 transactions to mine a block" << endl;
    }
    
    return 0;
    //end of code 
}