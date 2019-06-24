def parse_binary_bad(file)
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
    # this is a manual little endian to big endian swap --> these were converted incorrectly as they were little endian but you specified them as big endian
    [0, 4, 8, 12].each do |i| # swap each of the 4 4 byte headers how you believe they should be swapped dear god
      all_bytes[0 + i], all_bytes[3 + i] = all_bytes[3 + i], all_bytes[0 + i] # because you did big H H* you don't have to reverse the strings at least that's nice hmm
      all_bytes[1 + i], all_bytes[2 + i] = all_bytes[2 + i], all_bytes[1 + i]
    end
    packet_length = all_bytes[8..11].join.to_i(16) # omfg now it works just magically perfectly holy fuck god thank god yes lmao # type the command man pcap-savefile to read about these per-file headers as well as the main pcap file header
    all_pcap_packets << [all_bytes.shift(16), all_bytes.shift(packet_length)] # the per-packet header is 16 bytes + the packet_length to get the whole length of the packet love it
  end
  all_ethernet_frames = Array.new
  all_pcap_packets.each do |packet|
    all_ethernet_frames << [packet[1][0..5].join(":"), packet[1][6..11].join(":"), packet[1][12..13].join, packet[1][14..-1]] # source MAC address, destination MAC address, IP version, packet payload, https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
  end
  all_ip_datagrams = Array.new
  all_ethernet_frames.each do |frame|
    all_ip_datagrams << [frame[3][0], frame[3][1], frame[3][2..3].join, frame[3][4..5].join, frame[3][6..7].join, frame[3][8], frame[3][9], frame[3][10..11].join, frame[3][12..15].map { |hex| hex.to_i(16) }.join("."), frame[3][16..19].map { |hex| hex.to_i(16) }.join("."), frame[3][20..-1]] # in the array, index 0 is the Version and IHL, 1 is DSCP and ECN, 2 is Total Length, 3 is Identification, 4 is Flags and Fragment Offset, 5 is Time to Live, 6 is Protocol, 7 is Header Checksum, 8 is Source IP Address, 9 is Destination IP Address, and 10 is the actual payload lol https://en.wikipedia.org/wiki/IPv4#Header
  end
  all_tcp_segments = Array.new
  all_ip_datagrams.each do |dg|
    tcp_header_size = (dg[10][12][0].to_i(16) * 32) / 8 # the fucking TCP header is specified in 4 bits as a fucking 32 bit word (with 4 bits naturally the maximum number of words is 15) which gives teh minimum byte size of 20 bytes with 5 words and maximum byte size of 60 bytes so up to 40 bytes of options in the header to get this multiply the words by 32 to get the total bits and then divide by 8 to get the bytes lmao
    all_tcp_segments << [dg[10][0..1].join.to_i(16), dg[10][2..3].join.to_i(16), dg[10][4..7].join.to_i(16), dg[10][8..11].join, dg[10][12][0], dg[10][13], dg[10][14..15].join.to_i(16), dg[10][16..17].join, dg[10][18..19].join, dg[10][tcp_header_size..-1]] # index 0 is source port, 1 is destination port, 2 is sequence number, 3 is acknowledgement number, 4 is the data offset (size of the TCP header in 32 bit words lol), 5 are some flags, 6 is the window size, 7 is the checksum, 8 is the urgent pointer, and 9 is the actual data lol https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
  end
  all_received_tcp_segments = Array.new # as a hack everything from source port 80 going to destination port 59295
  all_tcp_segments.each do |seg|
    if seg[0] == 80 # then it must be sent from the HTTP server to us
      all_received_tcp_segments << seg
    end
  end
  all_received_tcp_segments.sort_by! { |seg| seg[2] } # right wireshark shows relative sequence numbers so this is actually okay whew
  # amazing this works perfectly to sort now just reject duplicates
  # puts all_received_tcp_segments.length # 55 received packets love it
  all_received_tcp_segments.uniq! { |seg| seg[2] } # reject all duplicate sequence numbers
  # puts all_received_tcp_segments.length # only 42 packets now so fucking great
  # now let's just combine the payloads together and then parse the HTTP data and you're good fuck yeah
  # p all_received_tcp_segments
  http_response_with_headers_hex = all_received_tcp_segments.map { |seg| seg[9] }.join
  # http_response_with_headers_bin = http_response_with_headers_hex.scan(/../).map { |x| x.hex.chr }.join # this does get you the headers nicely since those are correct text and you're getting that text now so you can confirm the headers are correct thank god this converts your hex into correct ASCII characters incorrect for what you want to do, but where you got the idea for thet scan with the awesome regex in it: https://anthonylewis.com/2011/02/09/to-hex-and-back-with-ruby/
  http_response_with_headers_bin = http_response_with_headers_hex.scan(/../).map { |two_hex| two_hex.to_i(16).to_s(2).rjust(two_hex.size*4, '0') }.join # the two_hex.size*4 just adjusts the size to be 4 digits long for each digit of hex since each digit of hex equals 4 digits of binary bits love it from https://stackoverflow.com/a/5981788/674794 two_hex_val.to_i(16).to_s(2).rjust(two_hex_val.size*4, '0') --> doing .to_s on integer will convert that integer to radix base 2 amazing and .to_i(16) will give the integer representation of that hex value amazing knowing that it's base/radix 16 amazing
  http_response_with_headers_text = http_response_with_headers_bin.scan(/......../).map { |eight_bit| eight_bit.to_i(2).chr }.join # fucking killed it figured that out entirely on your own
  puts http_response_with_headers_text[0..357] # the entire header
  p http_response_with_headers_text.inspect.index('\r\n\r\n') # use single quotes not double quotes, very strange that this returns 385 when it should actually be 358 hmm inspect returns the correct representation where \r\n\r\n would be found in so great
  p http_response_with_headers_text.inspect[0..398] # fucking insane the inspect adds two slashes to ESCAPE the escape characters LOL god damn hence why it's longer it no good way to do it like that you should just do it in binary man
  p http_response_with_headers_text[358..361] # the carriage return is the first \r\n\r\n fuck yes
  http_response_body_hex = http_response_with_headers_text[362..-1]
  # http_response_body_bin = http_response_body_hex.each_byte.map { |chr| chr.to_s(16).to_i(16).to_s(2).rjust(4, '0') }.join # this should be the full thing then okay good luck let's do it --> amazing the fucking each byte thing from https://anthonylewis.com/2011/02/09/to-hex-and-back-with-ruby/
  # p http_response_body_bin # --> all the hex of the actual data is here
  IO.write("output", http_response_body_hex) # so the output you've written here is actually just the byte stream, the .chr turns it into the right format that you can actually use to correctly write this as a binary bytestream, your key hint was putsing this gave you the exact same unreadable output you got when you puts the original IO stuff but now you need to understand this way more in depth so let's get to it :)
end

# remaining steps to parse the TCP segments into a coherent HTTP response to parse into the image
# 1. Get all the responses only, so sort by the correct source and destination addresses as is correct (everything from source 192.30.252.154 to 192.168.0.101 I believe, we are 192.168.0.101 ofc)
# 2. Sort all those responses by the TCP sequence number
# 3. Combine all the payload data from those sorted packets together
# 4. extract the HTTP header, decode it as plain text, read it
# 5. extract the HTTP body, write it to disk as a file with a .jpg extension, and open it

# careful notes: the 1490 byte length packets, plus one 452 and one 68 byte length packet at the end, should be all the packets that comprise the actual message
# Make sure to figure out whether or not to include retransmissions - retransmissions that come through are identical right and any of them are good?

# steps to doing the per packet parsing
# 1. Find the current packet's length read
# 2. Parse that length
# 3. Slice out the entire packet's header + length into all_packets
# 4. Find the next packet's length read, do the same thing, so a while loop love it

# next steps to refactor:
# 1. Do this all in binary

def parse_binary(file)
  input = File.new(file, 'r') # https://ruby-doc.org/core-2.6.3/File.html#method-c-new Right use File.new, not IO.new makes perf sense
  pcap_header = input.read(24) # save everything into a hash now love it instead of a read practice streaming --> defined on the IO class, can just specify a length to read in bytes, brilliant, exactly what you want lol https://ruby-doc.org/core-2.6.3/IO.html#method-i-read
  pcap_packets = Array.new # an array of hashes of packets
  curr_pcap_file_header = input.read(16) # preserves the binary data love it saving it like this
  while curr_pcap_file_header # input.read(16) will return nil specifically because it has a length specified amazing to do this actually right, so this will be true as long as there are still headers to read love it
    current_packet = { "header" => curr_pcap_file_header }
    packet_length = curr_pcap_file_header[8..11].unpack('V')[0] # the packet length is stored here in these 4 bytes https://ruby-doc.org/core-2.6.3/String.html#method-i-unpack v is a 32 bit unsigned integer which this is lol 4 bytes love it
    p packet_length # totally amazing this totally does read all the integers correctly in little endian yeah if you specify little endian for something that is little endian it'll read it correctly and for big endian it'll do it correctly fucking love it man Ruby et al such high level amazing languages lol
    current_packet["payload"] = input.read(packet_length) # this streaming way of reading the file is really perfect man
    pcap_packets << current_packet
    curr_pcap_file_header = input.read(16) # omfg works perfectly...could possibly do this with a do-while loop instead but don't think that works actually would have an empty packet at the end possibly could also just use a break statement in here
  end
  p pcap_packets.length
end

parse_binary('net.cap')
