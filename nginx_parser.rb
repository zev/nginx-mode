# Scan through nginx source code for ngx_command_t declarations.
# Find the ngx_string for the command and extract.
# Also the following line of NGX_ bit mask constants.
# if NGX_CONF_BLOCK then this is a command that defines a block and
# thus another indentation level.
# The other commands declare where the command is valid

CMD_DECL_START_REG = /static\s+ngx_command_t\s+.*\[\]\s*=\s*\{/
CMD_DECL_STOP_REG = /ngx_null_command|\};/
CMD_NAME_REG = /\{\s*ngx_string\s*\("(.*)"\)\s*,/

commands = Hash.new
command_types = Hash.new { |h,k| h[k] = [] }

in_command_declaration = false
current_command = nil
valid_locs = nil

ARGF.each_line do |line|
  if in_command_declaration
    if CMD_DECL_STOP_REG =~ line
      current_command = nil
      in_command_declaration = false
    elsif current_command && valid_locs.nil?
      valid_locs = line.strip.chomp.split("|")
      commands[current_command] = valid_locs
      valid_locs.each { |l| command_types[l] << current_command }
      current_command = nil
    elsif current_command.nil?
      if m = CMD_NAME_REG.match(line)
        current_command = m[1]
        valid_locs = nil
      end
    else
      #skip
    end
  else
    in_command_declaration = CMD_DECL_START_REG =~ line
  end
end

def command_list(cmds)
  "'(" + cmds.map { |c| "\"#{c}\""}.join(" ") + ")"
end

puts "Commands", command_list(commands.keys.sort)
puts "", ""
puts "Block Commands", command_list(command_types["NGX_CONF_BLOCK"].sort)
