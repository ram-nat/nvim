local function parse_netrw_uri(uri)
  -- Example: scp://user@host//path/to/file
  local protocol, user, host, path = uri:match("^([%w]+)://([^@]+)@([^/]+)//(.+)$")
  if protocol and user and host and path then
    return {
      protocol = protocol,
      user = user,
      host = host,
      path = "/" .. path,
    }
  else
    error("Could not parse netrw URI: " .. tostring(uri))
  end
end

local function sudo_write_remote()
  local uri = vim.api.nvim_buf_get_name(0)
  if vim.b.remote_sudo_meta then
    uri = vim.b.remote_sudo_meta.original_uri
  end
  local info = parse_netrw_uri(uri)

  -- Check if remote file is writable
  local check_writable_cmd = string.format("ssh %s@%s 'test -w %q'", info.user, info.host, info.path)
  local writable = (os.execute(check_writable_cmd) == 0)

  if writable then
    -- Use netrw's normal write
    vim.cmd("write")
    vim.notify(string.format("Saved %s to %s", info.path, info.host), vim.log.levels.INFO)
    return
  end

  -- Write buffer to a temporary local file
  local tmp_local = os.tmpname()
  vim.api.nvim_command("write! " .. tmp_local)

  -- Compose remote temporary file path
  local filename = vim.fn.fnamemodify(info.path, ":t")
  local remote_tmp = "/tmp/" .. filename .. "." .. info.user

  -- Copy local temp file to remote /tmp
  local scp_cmd = string.format("scp %s %s@%s:%s", tmp_local, info.user, info.host, remote_tmp)
  local scp_result = os.execute(scp_cmd)
  if scp_result ~= 0 then
    vim.notify("Failed to copy file to remote host!", vim.log.levels.ERROR)
    os.remove(tmp_local)
    return
  end

  -- Check if sudo requires a password on the remote host
  local check_sudo_cmd = string.format("ssh %s@%s 'sudo -n true'", info.user, info.host)
  local needs_password = (os.execute(check_sudo_cmd) ~= 0)

  local sudo_pass = ""
  local sudo_prefix = "sudo"
  if needs_password then
    sudo_pass = vim.fn.inputsecret("Remote sudo password: ")
    if sudo_pass == "" then
      vim.notify("No password entered, aborting.", vim.log.levels.WARN)
      os.remove(tmp_local)
      return
    end
    sudo_prefix = string.format("echo '%s' | sudo -S", sudo_pass)
  end

  -- Compose SSH script to:
  -- 1. Capture original mode, owner, group
  -- 2. Move the file as root
  -- 3. Restore original mode, owner, group
  local ssh_script = string.format(
    [[
orig_mode=$(stat -c "%%a" %s 2>/dev/null || echo "");
orig_owner=$(stat -c "%%u" %s 2>/dev/null || echo "");
orig_group=$(stat -c "%%g" %s 2>/dev/null || echo "");
%s mv %s %s;
if [ -n "$orig_owner" ] && [ -n "$orig_group" ]; then %s chown $orig_owner:$orig_group %s; fi;
if [ -n "$orig_mode" ]; then %s chmod $orig_mode %s; fi
]],
    info.path,
    info.path,
    info.path,
    sudo_prefix,
    remote_tmp,
    info.path,
    sudo_prefix,
    info.path,
    sudo_prefix,
    info.path
  )

  -- Write the SSH script to a temporary file to avoid shell quoting issues
  local tmp_script = os.tmpname()
  local f = io.open(tmp_script, "w")
  f:write(ssh_script)
  f:close()

  local ssh_cmd = string.format("ssh %s@%s 'bash -s' < %s", info.user, info.host, tmp_script)
  local ssh_result = os.execute(ssh_cmd)

  -- Clean up
  os.remove(tmp_local)
  os.remove(tmp_script)

  if ssh_result ~= 0 then
    vim.notify("Failed to move file into place as root on remote host!", vim.log.levels.ERROR)
    return
  end

  vim.notify(string.format("Saved %s to %s as root (attributes preserved)", info.path, info.host), vim.log.levels.INFO)
end

local function open_remote_with_sudo(opts)
  local uri = opts.args
  if uri == "" then
    uri = vim.fn.input("Remote URI to open (e.g. scp://user@host//path: ")
    if uri == "" then
      vim.notify("No URI provided, aborting", vim.log.levels.WARN)
      return
    end
  end
  local info = parse_netrw_uri(uri)

  -- Prompt for sudo password only if needed
  local check_sudo_cmd = string.format("ssh %s@%s 'sudo -n true'", info.user, info.host)
  local needs_password = (os.execute(check_sudo_cmd) ~= 0)
  local sudo_pass = ""
  local sudo_prefix = ""
  if needs_password then
    sudo_pass = vim.fn.inputsecret("Remote sudo password: ")
    if sudo_pass == "" then
      vim.notify("Aborted: No password entered", vim.log.levels.WARN)
      return
    end
    sudo_prefix = string.format("echo '%s' | sudo -S", sudo_pass)
  else
    sudo_prefix = "sudo"
  end

  -- Fetch file via sudo
  local tmp_file = os.tmpname()
  local fetch_cmd = string.format("ssh %s@%s '%s cat %q' > %s", info.user, info.host, sudo_prefix, info.path, tmp_file)

  if os.execute(fetch_cmd) ~= 0 then
    vim.notify(string.format("Failed to fetch file %s on %s with sudo", info.path, info.host), vim.log.levels.ERROR)
    os.remove(tmp_file)
    return
  end

  vim.cmd("edit " .. tmp_file)
  local meta = {
    original_uri = uri,
    host = info.host,
    user = info.user,
    path = info.path,
    tmp_path = tmp_file,
  }
  -- Find the buffer number by file name
  local bufnr = nil
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_get_name(buf) == tmp_file then
      bufnr = buf
      break
    end
  end

  if bufnr then
    vim.api.nvim_buf_set_var(bufnr, "remote_sudo_meta", meta)
  else
    error(string.format("Unable to set remote metadata for %s - Try reopening the file.", tmp_file))
  end

  vim.notify(string.format("File %s opened as %s on host %s", info.path, "root", info.host), vim.log.levels.INFO)
end

local function open_remote_smart(opts)
  local uri = opts.args
  if uri == "" then
    uri = vim.fn.input("Remote URI to open (e.g. scp://user@host//path: ")
    if uri == "" then
      vim.notify("No URI provided, aborting", vim.log.levels.WARN)
      return
    end
  end
  local info = parse_netrw_uri(uri)

  local check_readable_cmd = string.format("ssh %s@%s 'test -r %q'", info.user, info.host, info.path)
  local readable = (os.execute(check_readable_cmd) == 0)

  if readable then
    vim.cmd("edit " .. vim.fn.fnameescape(uri))
    vim.notify(string.format("File %s opened as %s on host %s", info.path, info.user, info.host), vim.log.levels.INFO)
    return
  end

  -- Check if parent directory is writable
  local dirname = vim.fn.fnamemodify(info.path, ":h")
  local check_dir_writable = string.format("ssh %s@%s 'test -w %q'", info.user, info.host, dirname)
  local dir_writable = (os.execute(check_dir_writable) == 0)

  if dir_writable then
    -- File does not exist, try to create it
    local touch_cmd = string.format("ssh %s@%s 'touch %q'", info.user, info.host, info.path)
    if os.execute(touch_cmd) == 0 then
      vim.cmd("edit " .. vim.fn.fnameescape(uri))
      vim.notify(string.format("File %s opened as %s on host %s", info.path, info.user, info.host), vim.log.levels.INFO)
      return
    else
      -- Could not create file, escalate to sudo
      vim.cmd("OpenRemoteWithSudo " .. vim.fn.fnameescape(uri))
      return
    end
  else
    -- Directory not writable, escalate to sudo
    vim.cmd("OpenRemoteWithSudo " .. vim.fn.fnameescape(uri))
    return
  end
end

vim.api.nvim_create_autocmd("FileType", {
  pattern = "netrw",
  callback = function()
    vim.keymap.set("n", "<leader>ro", function()
      local netrw_curdir = vim.b.netrw_curdir or ""
      local filename = vim.fn.expand("<cfile>")
      local needs_slash = netrw_curdir:sub(-1) ~= "/" and filename:sub(1, 1) ~= "/"
      local full_uri = needs_slash and (netrw_curdir .. "/" .. filename) or (netrw_curdir .. filename)
      if filename:sub(-1) == "/" then
        return
      end -- skip directories
      open_remote_smart({ args = full_uri })
    end, { buffer = true, noremap = true, silent = true })
  end,
})

vim.api.nvim_create_user_command("OpenRemoteSmart", open_remote_smart, { nargs = "?" })
vim.api.nvim_create_user_command("OpenRemoteWithSudo", open_remote_with_sudo, { nargs = "?" })
vim.api.nvim_create_user_command("SudoWriteRemote", sudo_write_remote, {})
