# NDN Link Quality Handler

## Mirror
If you are viewing this from a mirror then please visit `https://github.com/NDNAppBachelorThesis/ndn-link-quality-handler` to
access the build artifacts


# Get started developing
To get started developing locally do the following steps:
1. Install the required dependencies using maven. 
2. Run the ``Main.kt`` file with the ``NDN_HOST`` environment variable set to the IP of the ndn host. For this to work NDN must be running. You also need to specify the `NDN_ID` environment variables. This can basically be any number, as long as it's unique accross the NDN network. No two link quality handlers can have the same id
