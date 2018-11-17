import operator

# this is by no means well written.
# as it is now, for each mac address we reopen the .txt file and parse through it again and again and again....
# was a quick/dirty way to get an overall osGuess though
# this assumes you've done something like 'python3 satori.py -r pcaps/some.pcap -m dhcp > dhcp.txt' before hand
# if so then just run 'python parse.py > dhcp-guess.txt'
#
# again, this is VERY poorly written, but was just for quick POC

inputfile = "dhcp.txt"
macs = []
with open(inputfile, "r") as infile:
  for line in infile:
    parse = line.split(";")
    mac = parse[2]
    if mac not in macs:
      macs.append(mac)

for mac in macs:
  firstSeen = ''
  lastSeen = ''
  IP = ''
  signatures = []
  with open(inputfile, "r") as infile:
    for line in infile:
      parse = line.split(";")
      currentTime = parse[0]
      currentIP = parse[1]
      mac2 = parse[2]
      test = parse[3]
      if mac == mac2:
        IP = currentIP
        if (currentTime < firstSeen) or (firstSeen == ''):
          firstSeen = currentTime
        if currentTime > lastSeen:
          lastSeen = currentTime
        if test == 'DHCP':
          msgType = parse[4]
          cmd = parse[5]
          sig = parse[6]
          guess = parse[7]
          #cleanup any \r and \n that may be in the guess for end of line stuff
          guess = guess.replace('\n', '')
          guess = guess.replace('\r', '')
          signature = msgType + ';' + cmd + ';' + sig + ';' + guess
          if (signature not in signatures):
            signatures.append(signature)

  sigList = []
  for signature in signatures:
    parse = signature.split(";")
    guess = parse[3]
    sigs = guess.split("|")
    for sig in sigs:
      sigList.append(sig)

  overallSig = {}
  for sig in sigList:
    if sig != '':
      try:
        parse = sig.split(":")
        os = parse[0]
        score = int(parse[1])
        if os in overallSig:
          oldValue = int(overallSig.get(os))
          overallSig[os] = oldValue + score
        else:
          overallSig[os] = score
      except:
        pass

  sortedSig = sorted(overallSig.items(), key=operator.itemgetter(1),reverse=True)

  signature = ''
  for key, value in sortedSig:
    signature = signature + '|' + key + ':' + str(value)

  print(mac + ';' + IP + ';' + firstSeen + ';' + lastSeen + ';' + signature[1:])

