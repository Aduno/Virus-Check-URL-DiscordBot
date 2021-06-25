import discord
import time
import requests
import json


client = discord.Client()


vtToken = 'TOKEN FOR VIRUSTOTAL'
discordToken = 'TOKEN FOR BOT'
url = 'https://www.virustotal.com/vtapi/v2/url/report'
elapsed = 0.0


# Gets the time elapsed since last request
def time_since_request():
    return time.time()-elapsed


@client.event
async def on_ready():
    print('Logged in as {0.user}'.format(client))


@client.event
async def on_message(message):
    # Prevents the bot from doing anything from its own output
    if message.author == client.user:
        return

    msg = message.content

    # Checks if the user sent the keyword check at the front and it has been more than 15 seconds since the last request
    if msg.startswith('check') and time_since_request() > 15:

        # Validing user input
        urlToScan = msg.split(' ')
        if(len(urlToScan) == 1):  # Makes sure it isn't empty to prevent IndexOutofBounds
            await message.channel.send("Please enter a URL")
        else:
            urlToScan = urlToScan[1]

            # Makes sure it is a link
            if(urlToScan[0:4] == "http" and "." in urlToScan):
                # Extracts the url from the user to scan and sends a request to the VirusTotal api
                params = {'apikey': vtToken, 'resource': urlToScan}
                response = requests.get(url, params=params)
                response_json = json.loads(response.content)

                # Updates the request time
                global elapsed
                elapsed = time.time()

                # Checks if it has been flagged and sends a message accordingly

                if response_json['positives'] > 0:
                    await message.channel.send("Potenially malicious")
                else:
                    await message.channel.send("Not malicious")
                    await message.channel.send("Note: This is not fool-proof! Use common sense when opening unknown links")

            # If the user enters an invalid link
            else:
                await message.channel.send("Please enter a valid URL")
    elif msg.startswith('check') and time_since_request() < 15:
        await message.channel.send("Please wait "+str(round(15-time_since_request()))+" seconds "+" before checking another URL")

client.run(discordToken)
