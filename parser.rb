require 'byebug'

def parse_binary(file)
  raw_data = IO.read(file, encoding: "ASCII-8BIT", mode: "rb") # read-only in binary mode https://ruby-doc.org/core-2.5.0/IO.html#method-c-read
  # https://ruby-doc.org/core-2.5.3/String.html#method-i-unpack
  hex_data = raw_data.unpack('H*') # an asterisk keeps going lol --> this did indeed unpack it amazing. H is the right one, h for hexadecimal lsb, b for binary lsb
  # you need to unpack the first header to make sure it's in the right order though --> okay so this translates them correctly into the 8s hmmm fuck
  # bin_data = raw_data.unpack('b*') # basically in the end skip this line once you know your code is working well to do it correctly on the raw data hmm
  # without_pcap_headers = bin_data[0][192..-1] # remove the first 192 bits which are the first 24 bytes which is the length of the pcap header
  # without_first_header = without_pcap_headers[32..-1]
  # without_first_packet = without_first_header[156..-1] # fucking perfect it worked omg wow. So yeah you need to find the first 16 digits and remove them, read the next 2 digits, then keep parsing and splitting the file like that let's do it and then sleep
  # puts without_first_header[0..63]
  without_pcap_headers = hex_data[0][48..-1] #2 digits are a byte so the first 48 digits are the first 24 bytes so remove those
  all_pcap_packets = Array.new
  all_bytes = without_pcap_headers.chars.each_slice(2).map(&:join) # https://stackoverflow.com/questions/12039777/how-to-split-a-string-in-x-equal-pieces-in-ruby
  while all_bytes.length > 0 # amazing this actually does get exactly 99 packets and works perfectly
    # swap the damn headers lmao fuckkkk there obviously is a better way to do this but ah well. Every 4 bytes is one whole thing that needs to be swapped I believe
    [0, 4, 8, 12].each do |i| # swap each of the 4 4 byte headers how you believe they should be swapped dear god
      all_bytes[0 + i], all_bytes[3 + i] = all_bytes[3 + i], all_bytes[0 + i] # because you did big H H* you don't have to reverse the strings at least that's nice hmm
      all_bytes[1 + i], all_bytes[2 + i] = all_bytes[2 + i], all_bytes[1 + i]
    end
    packet_length = all_bytes[8..11].join("").to_i(16) # omfg now it works just magically perfectly holy fuck god thank god yes lmao
    all_pcap_packets << [all_bytes.shift(16), all_bytes.shift(packet_length)] # the per-packet header is 16 bytes + the packet_length to get the whole length of the packet love it
  end
  all_ethernet_frames = Array.new
  all_pcap_packets.each do |packet|
    all_ethernet_frames << [packet[1][0..5].join(":"), packet[1][6..11].join(":"), packet[1][12..13].join(""), packet[1][14..-1]] # source MAC address, destination MAC address, IP version, packet payload
  end
  all_ip_datagrams = Array.new
  all_ethernet_frames.each do |frame|
    all_ip_datagrams << [frame[3][0], frame[3][1], frame[3][2..3].join(""), frame[3][4..5].join(""), frame[3][6..7].join(""), frame[3][8], frame[3][9], frame[3][10..11].join(""), frame[3][12..15].map { |hex| hex.to_i(16) }.join("."), frame[3][16..19].map { |hex| hex.to_i(16) }.join("."), frame[3][20..-1]] # in the array, index 0 is the Version and IHL, 1 is DSCP and ECN, 2 is Total Length, 3 is Identification, 4 is Flags and Fragment Offset, 5 is Time to Live, 6 is Protocol, 7 is Header Checksum, 8 is Source IP Address, 9 is Destination IP Address, and 10 is the actual payload lol
  end
  p all_ip_datagrams
end

# steps to doing the per packet parsing
# 1. Find the current packet's length read
# 2. Parse that length
# 3. Slice out the entire packet's header + length into all_packets
# 4. Find the next packet's length read, do the same thing, so a while loop love it

parse_binary('net.cap')