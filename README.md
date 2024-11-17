# Willi 
Digital assets are gaining mainstream adoption, but not many people are thinking about ways to leave behind their digital assets for their loved ones. As a result, millions of cryptocurrency are stuck in wallets with no recovery mechanism. Willi is a solution for users to create wills for their digital assets, so that their relatives can claim their wallets should something untoward happen to the user.


# Overview
The owner has a smart account with the assets deposited. The smart account is deployed when the owner signs in with an email and makes a transaction. We use the multiowner light account by the Alchemy account kit such that more owners can be added. 

When the owner wants to create a will, it triggers the WillFactory.sol smart contract, which deploys a Will.sol smart contract. The smart account then adds the newly deployed Will.sol smart contract to it's owners.

The Will.sol smart contract stores the beneficiaries and controls the time in which the beneficiaries have the option to claim the smart account. The owner has to consistently send a transaction to prove that the owner is alive. If the owner does not send a transaction within the time frame, he is assumed to be dead, and any one of the beneficiaries can call the claimAccount transaction which adds the beneficiary's account as an owner. 

# User Flow



# Will Plugin
We experimented with two ways to perform the in
We have utilized the Alchemy Account Kit to do account abstraction.

The first was the one described above.

The second is a will plugin which has not been tested.
The Will Plugin is an experimental ERC6900-compatible plugin that tracks the time last active. It makes use of the preexecution hook to set the lastActiveTime so there is no need to call a specific alive transaction.
