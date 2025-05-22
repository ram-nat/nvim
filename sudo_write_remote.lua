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

-- Helper to get the sudo prefix for remote commands, prompting for password if needed.
-- If password entry is aborted, it cleans up tmp_local_to_cleanup_on_abort (if provided) and errors out.
local function get_remote_sudo_prefix(user, host, tmp_local_to_cleanup_on_abort)
  local check_sudo_cmd = string.format("ssh %s@%s 'sudo -n true'", user, host)
  local needs_password = (os.execute(check_sudo_cmd) ~= 0)
  local sudo_pass = ""
  local sudo_prefix = "sudo"
  if needs_password then
    sudo_pass = vim.fn.inputsecret("Remote sudo password: ")
    if sudo_pass == "" then
      vim.notify("No password entered. Aborting sudo operation.", vim.log.levels.WARN)
      if tmp_local_to_cleanup_on_abort then
        os.remove(tmp_local_to_cleanup_on_abort)
        vim.notify("Cleaned up temporary file: " .. tmp_local_to_cleanup_on_abort, vim.log.levels.INFO)
      end
      return nil -- Signal that the user aborted, notifications and cleanup for this path are done.
    end
    sudo_prefix = string.format("echo %s | sudo -S", vim.fn.shellescape(sudo_pass))
  end
  return sudo_prefix
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
  vim.api.nvim_command("write! " .. vim.fn.fnameescape(tmp_local))

  -- Compose remote temporary file path with better uniqueness
  local filename = vim.fn.fnamemodify(info.path, ":t")
  local pid = tostring(vim.fn.getpid())
  local rand = tostring(math.random(100000, 999999))
  local remote_tmp = string.format("/tmp/%s.%s.%s.%s", filename, info.user, pid, rand)

  -- Copy local temp file to remote /tmp
  local scp_cmd = string.format(
    "scp %s %s@%s:%s",
    vim.fn.shellescape(tmp_local),
    info.user,
    info.host,
    vim.fn.shellescape(remote_tmp)
  )
  local scp_result = os.execute(scp_cmd)
  if scp_result ~= 0 then
    vim.notify("Failed to copy file to remote host!", vim.log.levels.ERROR)
    os.remove(tmp_local)
    return
  end

  -- Get sudo prefix (may prompt for password)
  local sudo_prefix = get_remote_sudo_prefix(info.user, info.host, tmp_local)
  if not sudo_prefix then
    -- If sudo_prefix is nil, it means get_remote_sudo_prefix handled user notification
    -- and cleanup (like tmp_local) for the password cancellation.
    -- So, we just abort this function.
    return -- Abort sudo_write_remote
  end

  local ssh_script_content = string.format(
    [[
#!/bin/bash
TARGET_PATH="$1"
REMOTE_TMP_PATH="$2"
  
orig_mode=$(stat -c "%%a" "${TARGET_PATH}" 2>/dev/null || echo "");
orig_owner=$(stat -c "%%u" "${TARGET_PATH}" 2>/dev/null || echo "");
orig_group=$(stat -c "%%g" "${TARGET_PATH}" 2>/dev/null || echo "");
  
# Execute move command with sudo_prefix
%s mv -f "${REMOTE_TMP_PATH}" "${TARGET_PATH}";
if [ $? -ne 0 ]; then
  # Attempt to clean up remote temp file if move failed, then exit
  %s rm -f "${REMOTE_TMP_PATH}"
  exit 1;
fi
  
# Restore owner/group if they were captured
if [ -n "$orig_owner" ] && [ -n "$orig_group" ]; then
  %s chown "$orig_owner:$orig_group" "${TARGET_PATH}";
fi;
  
# Restore mode if it was captured
if [ -n "$orig_mode" ]; then
  %s chmod "$orig_mode" "${TARGET_PATH}";
fi;
exit 0
]],
    sudo_prefix,
    sudo_prefix,
    sudo_prefix,
    sudo_prefix
  ) -- sudo_prefix is used for mv, rm (on fail), chown, chmod

  local tmp_script_file_path = nil -- Will hold the path if script file is successfully created
  local ssh_exit_code = -1 -- Initialize with a value indicating not yet run or error

  local pcall_success -- Boolean: Did pcall itself succeed (no Lua error in the anonymous function)?
  local os_exec_status -- First return from os.execute (true, false, or nil)
  local os_exec_code_or_msg -- Second return from os.execute (exit code as number, or error message as string)
  -- local os_exec_signal      -- Third return from os.execute (term signal), not used here
  pcall_success, os_exec_status, os_exec_code_or_msg = pcall(function()
    tmp_script_file_path = os.tmpname() -- Generate name for the script file
    local f = io.open(tmp_script_file_path, "w")
    if not f then
      error("Failed to create temporary script file: " .. tmp_script_file_path) -- This error is caught by pcall
    end
    -- File is open, write to it
    f:write(ssh_script_content)
    f:close()
    -- tmp_script_file_path now points to a created and populated file

    local ssh_cmd = string.format(
      "ssh %s@%s 'bash -s %s %s' < %s",
      info.user,
      info.host,
      vim.fn.shellescape(info.path),
      vim.fn.shellescape(remote_tmp),
      vim.fn.shellescape(tmp_script_file_path)
    )

    return os.execute(ssh_cmd) -- Returns (status, code_or_msg, signal)
  end)

  -- **Guaranteed Cleanup Section**

  -- 1. Clean up the temporary script file, if its path was determined and file exists.
  if tmp_script_file_path and vim.fn.filereadable(tmp_script_file_path) == 1 then
    os.remove(tmp_script_file_path)
  end

  -- 2. Clean up the local temporary content file.
  --    It should exist at this point unless get_remote_sudo_prefix errored (which would have halted execution).
  if vim.fn.filereadable(tmp_local) == 1 then
    os.remove(tmp_local)
  end

  -- **Process the result of the pcall'd operations**
  if not pcall_success then
    -- A Lua error occurred within the pcall block (e.g., io.open failed and error() was called).
    -- In this case, os_exec_status (the second value from pcall) holds the error object.
    vim.notify("Error during remote script execution preparation: " .. tostring(os_exec_status), vim.log.levels.ERROR)
    return
  end

  -- If pcall succeeded, os_exec_status and os_exec_code_or_msg are from the os.execute() call
  if os_exec_status ~= true then
    vim.notify(string.format("SSH command failed: %s", tostring(os_exec_code_or_msg)), vim.log.levels.ERROR)
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

  -- Get sudo prefix (may prompt for password)
  local sudo_prefix = get_remote_sudo_prefix(info.user, info.host, nil) -- Pass nil for tmp_local_to_cleanup
  if not sudo_prefix then
    -- User aborted password entry, get_remote_sudo_prefix handled notifications.
    return -- Abort open_remote_with_sudo
  end

  -- Fetch file via sudo
  local tmp_file = os.tmpname()
  local fetch_cmd = string.format(
    "ssh %s@%s %s > %s",
    info.user,
    info.host,
    vim.fn.shellescape(string.format("%s cat %s", sudo_prefix, info.path)), -- Remote command
    vim.fn.shellescape(tmp_file)
  ) -- Local output file

  if os.execute(fetch_cmd) ~= 0 then
    vim.notify(string.format("Failed to fetch file %s on %s with sudo", info.path, info.host), vim.log.levels.ERROR)
    os.remove(tmp_file)
    return
  end

  vim.cmd("edit " .. vim.fn.fnameescape(tmp_file))
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
