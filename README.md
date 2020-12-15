

# blockchain-py


This is a fork of [blockchain-py](https://github.com/yummybian/blockchain-py)  witch is a python imlementation of [blockchain_go](https://github.com/Jeiwan/blockchain_go)

 

### what new is coming ??
* Graphical User interface -> (show balance, send coins, receive coins, start-stop mining, show blockchain info)
* Hard coded genesis block 
* Block validation
* Transaction validation
* Mining Difficulty adjustment 
* Peer-to-Peer (p2p)

### Peer-to-Peer (p2p)

Since this is a peer-to-peer network, every instance has to be both the a server and a client, both server and client starts with silme-qt, server runs under defaults [p2p] at silme.conf


 -   Boostrap by way of a preconfigured list
 -   Connect to other nodes and make a handshake.
 -   Ask peers for nodes and connect to them
 -   Ask peers if sync needed 
 -   Sync with peers if needed
 -   Ping peers
 -   Send new mined blocks to other peers
 -   Validate transactions and pass it to other peers 

### I have a question
* open a issue 

### I'm Developer
* Access the main.py file with your own risk (headache possible)
* Submit pull request 
* Fork it and start editing
* open a issue

### How to run it ??
Currenlty its tested only in windows, all work are done via main.py file, when you run main.py file a Graphical User interface will appear.
![ScreenShot](https://i.imgur.com/QtHxQx7.png)

%APPDATA%\mycoin is the default data dir path, contains your wallet both private and public keys, blockchain data, and a debug.log file wich stores 
informations* and errors that occur when running blockchain-py..


### Linux ??
Soon



[教程中文翻译](https://github.com/liuchengxu/blockchain-tutorial/blob/master/content/SUMMARY.md)

Thanks to [liuchengxu](https://github.com/liuchengxu) [yummybian](https://github.com/yummybian)
