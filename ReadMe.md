# Blockchain Project Assignment 1

### This project is a basic implementation of the consensus algorithm DPoS(Delegated Proof of Stake) in a blockchain for a Land Management System.

## Objective

### This assignment to build a land management system with the following features:

1. To register new users to the system with previously owned property
2. The user should be able to buy and sell the property.
3. To improve the security of the blockchain, incorporate a consensus algorithm that has been assigned to the group.
4. Implementation of Merkle root to calculate the hash of all the transactions in a block.
5. To be able to view the transaction history that is related to a property.

## Team members - (Group 18)

1. Riya Singh (2020A7PS2048H)
2. Ishika Bhola (2020A8PS1821H)
3. Afrin Karim (2020A7PS1311H)
4. Sanskar Sharma (2020A3PS2212H)

## Basic functionalities of our program-

### 1. Register New User

### 2. View Transaction History

### 3. Vote for Delegation

### 4. Buy property

### 5. Sell property

### 6. Mine Block

### 7. Exit

## Delegated Proof of Stake (DPoS) algorithm

Delegated proof of stake (DPoS) is a verification and consensus mechanism in the blockchain . It competes with other proof of work and proof of stake models as a way to verify transactions and promote blockchain organization.
A trustworthy, strong, scalable, and effective consensus method for blockchain technology is DPoS. It is an improvement above the common Proof of Stake (PoS). In DPoS, each node with a stake in the system has the ability to vote to assign other nodes the responsibility of validating transactions.
Here, in DPoS ,user's vote weight is proportional to their stake rather than block mining being tied to the stakeholders' total tokens.

# Blockchain Implementation


## The Blockchain class
    class Blockchain {
public:
    Blockchain();

    void AddBlock(Block bNew);

    vector<Block> vChain;

private:
    Block GetLastBlock() const;
};



## Implementation of DPoS in Land Management System's Blockchain

    vector<pair<int, int>> voting(){
    vector<pair<int, int>> votes(idStakes.size());

    for(int i=0; i<idStakes.size(); i++){
        votes[i]={idStakes[i]*(rand()%100), i};
    }

    sort(votes.begin(), votes.end(), greater<>());
    return votes;

}


## Hashing Algorithm using SHA256

SHA 256 is a part of the SHA 2 family of algorithms, where SHA stands for Secure Hash Algorithm. Published in 2001, it was a joint effort between the NSA and NIST to introduce a successor to the SHA 1 family, which was slowly losing strength against brute force attacks.

The significance of the 256 in the name stands for the final hash digest value, i.e. irrespective of the size of plaintext/cleartext, the hash value will always be 256 bits.

## Assigning Stakes

A user has to have enough stake in the system.
Each node that has a stake in the system can delegate the validation of a transaction to other nodes by voting in a democratic way.

void assignStakes(vector<Transaction>& allTrans, int idx)
{
    if(idStakes.find(idx)==idStakes.end())
    {
        idStakes[idx]=rand()%100;
    }
}


# Mining a Block (includes a simple program to print the list of selected delegates)
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

# Merkle Tree Implementation
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

## Hashing the Transactions
    inline string Transaction::CalculateTransHash() const
{
    stringstream ss;
    ss << buyerID << sellerID << landID << tTime;

    return sha256(ss.str());
}

## This function helps us calculate the root hash of a particular block.
The merkle root of the block gives us the summary of all the transaction and their hashes via the merkle tree and is stored in the block header.

    inline string Block::CalculateHash() const
{
    stringstream ss;
    ss << nIndex << sPrevHash << trans1.tTime << trans1.buyerID << trans1.sellerID << trans2.tTime << trans2.buyerID << trans2.sellerID <<trans3.tTime << trans3.buyerID << trans3.sellerID<< nNonce;

    return sha256(ss.str());
}



## Function to transfer land
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


## Function to view transaction history of a land
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
