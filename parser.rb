def parse_binary(file)
  raw_data = IO.read(file, encoding: "ASCII-8BIT", mode: "rb") # read-only in binary mode https://ruby-doc.org/core-2.5.0/IO.html#method-c-read
  # https://ruby-doc.org/core-2.5.3/String.html#method-i-unpack
  hex_data = raw_data.unpack('H*') # an asterisk keeps going lol --> this did indeed unpack it amazing. H is the right one, h for hexadecimal lsb, b for binary lsb
  # you need to unpack the first header to make sure it's in the right order though --> okay so this translates them correctly into the 8s hmmm fuck
  # bin_data = raw_data.unpack('b*') # basically in the end skip this line once you know your code is working well to do it correctly on the raw data hmm
  # without_pcap_headers = bin_data[0][192..-1] # remove the first 192 bits which are the first 24 bytes which is the length of the pcap header
  without_pcap_headers = hex_data[0][48..-1] #2 digits are a byte so the first 48 digits are the first 24 bytes so remove those
  all_packets = Array.new
  all_bytes = without_pcap_headers.chars.each_slice(2).map(&:join) # https://stackoverflow.com/questions/12039777/how-to-split-a-string-in-x-equal-pieces-in-ruby
  while all_packets.length < 99 # hardcoded, you know there are 99 packets, let's figure out a better way once you get all the data in the first place
    packet_length = all_bytes[9].to_i(16) # the 9th byte is what encodes the length of the packet lol as long as the packet isn't too long kind of hacky technically it's 4 total bytes but only the last byte actually has data so far as you can tell def fix later though when you feel less hacky about it
    all_packets << all_bytes.shift(16 + packet_length) # the per-packet header is 16 bytes + the packet_length to get the whole length of the packet love it
  end
  without_first_packet = without_first_header[156..-1] # fucking perfect it worked omg wow. So yeah you need to find the first 16 digits and remove them, read the next 2 digits, then keep parsing and splitting the file like that let's do it and then sleep
  # puts without_first_header[0..63]
  p all_packets
  p all_bytes
end

# steps to doing the per packet parsing
# 1. Find the current packet's length read
# 2. Parse that length
# 3. Slice out the entire packet's header + length into all_packets
# 4. Find the next packet's length read, do the same thing, so a while loop love it

parse_binary('net.cap')