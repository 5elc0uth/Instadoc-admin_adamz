"use strict";

/**
 * Instadoc Admin Dashboard (Refactored)
 * - Unified activity feed via `platform_activity`
 * - Admin audit trail via `admin_audit_log`
 * - Soft-delete via `profiles.deleted_at` (exposed as Archived)
 * - Doctor ↔ Patient assignments via `doctor_patient_assignments`
 *
 * IMPORTANT SECURITY NOTE:
 * Using an ANON key in a client-side admin dashboard is not secure unless ALL write operations are protected
 * by RLS policies that only allow admins. Ideally, admin actions should go through server-side functions.
 */

/* =========================
   1) CONFIG
   ========================= */
const CONFIG = {
  SUPABASE_URL: "https://ioaqlcltvakuqqehkyor.supabase.co",
  SUPABASE_ANON_KEY:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlvYXFsY2x0dmFrdXFxZWhreW9yIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjYxNTk1MzksImV4cCI6MjA4MTczNTUzOX0._7ISJbfJzryBJWmtRuN72F-JZpYdvJxsltwwhombPtE",
};

const supabaseClient = supabase.createClient(
  CONFIG.SUPABASE_URL,
  CONFIG.SUPABASE_ANON_KEY,
);

/* =========================
   2) STATE
   ========================= */
const state = {
  sessionUser: null,
  currentAdminId: null,
  currentAdminName: null, // stored for use in activity descriptions
  selectedUserId: null,
  selectedTicketId: null,
  allUsers: [],
  allTickets: [],
  allDoctors: [],
  selectedDoctorId: null,
  selectedDoctorName: null,
  selectedDoctorEmail: null,
  assignments: [], // for selected doctor
  patientPicker: [],
  _sessionWatcher: null, // interval ID for session status polling
};

/* =========================
   3) DOM HELPERS
   ========================= */
const $ = (id) => document.getElementById(id);
const qs = (sel, root = document) => root.querySelector(sel);
const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function setBodyView(view) {
  const body = $("app-body");
  body.classList.remove("view-login", "view-dashboard");
  body.classList.add(view);
}

function show(el) {
  el?.classList.remove("hidden");
}
function hide(el) {
  el?.classList.add("hidden");
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showAlert(message) {
  const box = $("login-alert");
  box.textContent = message;
  show(box);
}

function clearAlert() {
  const box = $("login-alert");
  box.textContent = "";
  hide(box);
}

function setLoading(isLoading) {
  const btn = $("loginBtn");
  const text = btn?.querySelector(".btn-text");
  const loader = btn?.querySelector(".btn-loader");
  if (!btn || !text || !loader) return;
  if (isLoading) {
    btn.disabled = true;
    hide(text);
    show(loader);
  } else {
    btn.disabled = false;
    show(text);
    hide(loader);
  }
}

function formatDate(dateInput) {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return "N/A";
  const day = String(d.getDate()).padStart(2, "0");
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const year = d.getFullYear();
  return `${day}/${month}/${year}`;
}

function formatDateTime(dateInput) {
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return "N/A";
  const day = String(d.getDate()).padStart(2, "0");
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const year = d.getFullYear();
  const hours = d.getHours();
  const minutes = String(d.getMinutes()).padStart(2, "0");
  const ampm = hours >= 12 ? "PM" : "AM";
  const displayHours = hours % 12 || 12;
  return `${day}/${month}/${year}, ${displayHours}:${minutes} ${ampm}`;
}

function timeAgo(dateInput) {
  const date = new Date(dateInput);
  const seconds = Math.floor((new Date() - date) / 1000);
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes > 1 ? "s" : ""} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? "s" : ""} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days > 1 ? "s" : ""} ago`;
}

/* =========================
   4) NAV TABS
   ========================= */
function initTabs() {
  qsa(".nav-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      qsa(".nav-tab").forEach((b) => b.classList.remove("active"));
      qsa(".tab-content").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      const target = btn.dataset.target;
      $(`${target}`)?.classList.add("active");
    });
  });
}

/* =========================
   5) AUTH FLOW
   ========================= */
async function bootstrap() {
  initTabs();
  bindUI();

  const {
    data: { session },
    error,
  } = await supabaseClient.auth.getSession();
  if (error) console.warn("getSession error:", error);

  if (session?.user) {
    await checkAdminAndLoad(session.user);
  } else {
    showLogin();
  }
}

function showLogin() {
  setBodyView("view-login");
  show($("login-view"));
  hide($("dashboard-view"));
  clearAlert();
  setLoading(false);
}

function showDashboard() {
  setBodyView("view-dashboard");
  hide($("login-view"));
  show($("dashboard-view"));
}

async function checkAdminAndLoad(user) {
  clearAlert();
  setLoading(true);

  // Fetch role from profiles
  const { data: profile, error } = await supabaseClient
    .from("profiles")
    .select("id, role, status, deleted_at")
    .eq("id", user.id)
    .single();

  if (error) {
    showAlert(`Database Error: ${error.message}. Check RLS policies.`);
    await supabaseClient.auth.signOut();
    setLoading(false);
    return;
  }

  if (profile?.deleted_at) {
    showAlert("Access Denied: This account is archived.");
    await supabaseClient.auth.signOut();
    setLoading(false);
    return;
  }

  if (profile?.status === "suspended") {
    showAlert("Access Denied: This account has been suspended.");
    await supabaseClient.auth.signOut();
    setLoading(false);
    return;
  }

  if (profile?.role !== "admin") {
    showAlert(
      `Access Denied: Your role is '${profile?.role}', but 'admin' is required.`,
    );
    await supabaseClient.auth.signOut();
    setLoading(false);
    return;
  }

  state.sessionUser = user;
  state.currentAdminId = user.id;
  state.currentAdminName = profile.full_name || user.email || "Admin";
  $("admin-email").textContent = user.email;

  showDashboard();
  await loadAllData();
  setupRealtime();
  startSessionWatcher(user.id); // Poll every 60s to catch status changes mid-session

  setLoading(false);
}

// Polls profile every 60 seconds — kicks admin out if their OWN account is suspended/archived mid-session
function startSessionWatcher(userId) {
  // Clear any existing watcher
  if (state._sessionWatcher) clearInterval(state._sessionWatcher);

  state._sessionWatcher = setInterval(async () => {
    try {
      const { data: profile } = await supabaseClient
        .from("profiles")
        .select("status, deleted_at, role")
        .eq("id", userId)
        .single();

      const blocked =
        !profile ||
        profile.deleted_at !== null ||
        profile.status === "suspended" ||
        profile.role !== "admin";

      if (blocked) {
        clearInterval(state._sessionWatcher);
        await supabaseClient.auth.signOut();
        resetState();
        showLogin();
        showAlert("Your session has ended: account status changed by an administrator.");
      }
    } catch (_) {
      // Network hiccup — don't kick out, try again next cycle
    }
  }, 60000); // Check every 60 seconds
}


/* =========================
   6) UI BINDINGS
   ========================= */
function bindUI() {
  // Login submit
  $("loginForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearAlert();

    const email = $("email").value.trim();
    const password = $("password").value;

    setLoading(true);
    const { data, error } = await supabaseClient.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      showAlert(error.message);
      setLoading(false);
      return;
    }
    await checkAdminAndLoad(data.user);
  });

  // Logout
  $("logoutBtn")?.addEventListener("click", async () => {
    await supabaseClient.auth.signOut();
    resetState();
    showLogin();
  });

  // Users
  $("refreshUsersBtn")?.addEventListener("click", async () => {
    if ($("userSearch")) $("userSearch").value = "";
    if ($("roleFilter")) $("roleFilter").value = "all";
    if ($("statusFilter")) $("statusFilter").value = "all";

    state.selectedUserId = null;

    await loadUsers();
  });
  $("userSearch")?.addEventListener("input", () => applyUserFilters());
  $("roleFilter")?.addEventListener("change", () => applyUserFilters());
  $("statusFilter")?.addEventListener("change", () => applyUserFilters());

  // Create user modal
  $("openCreateUserBtn")?.addEventListener("click", () =>
    openCreateUserModal(),
  );
  $("closeCreateUserModalBtn")?.addEventListener("click", () =>
    closeCreateUserModal(),
  );
  $("createUserForm")?.addEventListener("submit", (e) => createUser(e));

  // User modal
  $("closeUserModalBtn")?.addEventListener("click", () => closeUserModal());

  // Metrics
  $("refreshLogsBtn")?.addEventListener("click", async () => {
    if ($("logTypeFilter")) $("logTypeFilter").value = "all";

    await loadRecentLogs();
    await loadActivityFeed();
  });
  $("logTypeFilter")?.addEventListener("change", () => loadRecentLogs());

  // Tickets
  $("refreshTicketsBtn")?.addEventListener("click", async () => {
    if ($("ticketSearch")) $("ticketSearch").value = "";
    if ($("priorityFilter")) $("priorityFilter").value = "all";
    if ($("ticketStatusFilter")) $("ticketStatusFilter").value = "all";

    state.selectedTicketId = null;

    closeTicketPanel();

    await loadTickets();
  });
  $("ticketSearch")?.addEventListener("input", () => applyTicketFilters());
  $("priorityFilter")?.addEventListener("change", () => applyTicketFilters());
  $("ticketStatusFilter")?.addEventListener("change", () =>
    applyTicketFilters(),
  );
  $("closeTicketPanelBtn")?.addEventListener("click", () => closeTicketPanel());
  $("sendTicketReplyBtn")?.addEventListener("click", () => sendTicketReply());

  // Doctors
  $("refreshDoctorsBtn")?.addEventListener("click", async () => {
    if ($("doctorSearch")) $("doctorSearch").value = "";

    state.selectedDoctorId = null;
    state.assignments = [];

    const patientList = $("patientList");
    if (patientList)
      patientList.textContent = "Select a doctor to view assigned patients.";

    $("openAssignPatientBtn").disabled = true;
    $("unassignAllBtn").disabled = true;

    await loadDoctors();
  });
  $("doctorSearch")?.addEventListener("input", () => filterDoctors());
  $("openAssignPatientBtn")?.addEventListener("click", () =>
    openAssignPatientModal(),
  );
  $("unassignAllBtn")?.addEventListener("click", () => unassignAllFromDoctor());

  // Assign patient modal
  $("closeAssignPatientModalBtn")?.addEventListener("click", () =>
    closeAssignPatientModal(),
  );
  $("patientSearch")?.addEventListener("input", () => renderPatientPicker());
  $("refreshPatientPickerBtn")?.addEventListener("click", () =>
    loadPatientPicker(),
  );
}

function resetState() {
  // Stop session watcher if running
  if (state._sessionWatcher) {
    clearInterval(state._sessionWatcher);
    state._sessionWatcher = null;
  }
  state.sessionUser = null;
  state.currentAdminId = null;
  state.currentAdminName = null;
  state.selectedUserId = null;
  state.allUsers = [];
  state.allTickets = [];
  state.allDoctors = [];
  state.selectedDoctorId = null;
  state.selectedDoctorName = null;
  state.selectedDoctorEmail = null;
  state.assignments = [];
  state.patientPicker = [];
}

/* =========================
   7) DATA LOADING (Top)
   ========================= */
async function loadAllData() {
  await Promise.allSettled([
    loadUsers(),
    loadMetrics(),
    loadTickets(),
    loadRecentLogs(),
    loadActivityFeed(),
    loadWeeklyChart(),
    loadDoctors(),
  ]);
}

/* =========================
   8) USER MANAGEMENT
   ========================= */
async function loadUsers() {
  const tbody = $("usersTableBody");
  tbody.innerHTML =
    '<tr><td colspan="8" class="empty-state">Fetching data...</td></tr>';

  // Include deleted_at so we can show Archived status
  const { data, error } = await supabaseClient
    .from("profiles")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="color:red">Error: ${escapeHtml(error.message)}</td></tr>`;
    return;
  }

  state.allUsers = data || [];
  applyUserFilters(); // renders
}

function normalizeUserStatus(u) {
  // Soft delete maps to archived
  if (u.deleted_at) return "archived";
  return u.status || "active";
}

function applyUserFilters() {
  const search = $("userSearch")?.value?.trim().toLowerCase() || "";
  const role = $("roleFilter")?.value || "all";
  const status = $("statusFilter")?.value || "all";

  let filtered = [...state.allUsers];

  if (search) {
    filtered = filtered.filter(
      (u) =>
        (u.email || "").toLowerCase().includes(search) ||
        (u.full_name || "").toLowerCase().includes(search) ||
        (u.id || "").toLowerCase().includes(search),
    );
  }

  if (role !== "all") {
    filtered = filtered.filter((u) => u.role === role);
  }

  if (status !== "all") {
    filtered = filtered.filter((u) => normalizeUserStatus(u) === status);
  }

  renderUsers(filtered);
}

function renderUsers(users) {
  const tbody = $("usersTableBody");
  tbody.innerHTML = "";

  if (!users.length) {
    tbody.innerHTML =
      '<tr><td colspan="8" class="empty-state">No users found matching your criteria.</td></tr>';
    return;
  }

  users.forEach((u) => {
    const status = normalizeUserStatus(u);
    const isSelf = state.currentAdminId && u.id === state.currentAdminId;

    const roleBadge =
      u.role === "admin"
        ? "badge-admin"
        : u.role === "doctor"
          ? "badge-doctor"
          : "badge-patient";

    const statusBadge = `badge-${status}`;

    const row = document.createElement("tr");
    row.dataset.userId = u.id;
    row.classList.add("selectable-row");

    if (state.selectedUserId === u.id) row.classList.add("selected");

    row.addEventListener("click", (e) => {
      // Don't toggle selection when clicking buttons inside row
      if (e.target.closest("button")) return;
      selectUserRow(u.id);
    });

    const actionButtons = buildUserActionButtons(u, status, isSelf);

    row.innerHTML = `
<td><small>${escapeHtml((u.id || "").substring(0, 8))}...</small></td>
      <td><strong>${escapeHtml(u.full_name || "N/A")}</strong></td>
      <td>${escapeHtml(u.email || "N/A")}</td>
      <td><span class="badge ${roleBadge}">${escapeHtml(u.role || "unknown")}</span></td>
      <td><span class="badge ${statusBadge}">${escapeHtml(status.toUpperCase())}</span></td>
      <td>${u.created_at ? escapeHtml(formatDate(u.created_at)) : "N/A"}</td>
      <td><div class="action-buttons">${actionButtons}</div></td>
    `;

    tbody.appendChild(row);
  });

  // Refresh selection indicator for all rows
  syncSelectedRowStyles();
}

function selectUserRow(userId) {
  state.selectedUserId = userId;
  syncSelectedRowStyles();
}

function syncSelectedRowStyles() {
  qsa("#usersTableBody tr").forEach((tr) => {
    const id = tr.dataset.userId;
    if (id && id === state.selectedUserId) {
      tr.classList.add("selected");
    } else {
      tr.classList.remove("selected");
    }
  });
}

// ----- Ticket row selection (tick/untick) -----
function selectTicketRow(ticketId) {
  if (state.selectedTicketId === ticketId) {
    state.selectedTicketId = null;
  } else {
    state.selectedTicketId = ticketId;
  }
  syncSelectedTicketStyles();
}

function syncSelectedTicketStyles() {
  document.querySelectorAll("#ticketTableBody tr").forEach((tr) => {
    const id = tr.dataset.ticketId;
    if (id && id === state.selectedTicketId) {
      tr.classList.add("selected");
    } else {
      tr.classList.remove("selected");
    }
  });
}

function buildUserActionButtons(u, status, isSelf) {
  const viewBtn = `<button class="btn btn-view" type="button" onclick="AdminApp.viewUser('${u.id}')">View</button>`;
  const editBtn = `<button class="btn btn-edit" type="button" onclick="AdminApp.editUser('${u.id}')">Edit</button>`;

  if (isSelf) {
    return `${viewBtn}${editBtn}<small style="color:#6c757d;font-style:italic;">Cannot modify own status</small>`;
  }

  const deactivateBtn = `<button class="btn btn-inactive" type="button" onclick="AdminApp.changeUserStatus('${u.id}','inactive')">Deactivate</button>`;
  const suspendBtn = `<button class="btn btn-suspend" type="button" onclick="AdminApp.changeUserStatus('${u.id}','suspended')">Suspend</button>`;
  const activateBtn = `<button class="btn btn-activate" type="button" onclick="AdminApp.changeUserStatus('${u.id}','active')">Activate</button>`;
  const archiveBtn = `<button class="btn btn-close" type="button" onclick="AdminApp.archiveUser('${u.id}')">Archive</button>`;
  const restoreBtn = `<button class="btn btn-activate" type="button" onclick="AdminApp.restoreUser('${u.id}')">Restore</button>`;

  if (status === "archived") {
    return `${viewBtn}${editBtn}${restoreBtn}`;
  }

  if (status === "active")
    return `${viewBtn}${editBtn}${deactivateBtn}${suspendBtn}${archiveBtn}`;
  if (status === "inactive")
    return `${viewBtn}${editBtn}${activateBtn}${suspendBtn}${archiveBtn}`;
  if (status === "suspended")
    return `${viewBtn}${editBtn}${activateBtn}${archiveBtn}`;

  return `${viewBtn}${editBtn}${archiveBtn}`;
}

async function viewUser(userId) {
  const u = state.allUsers.find((x) => x.id === userId);
  if (!u) return;

  const modal = $("userModal");
  const body = $("userModalBody");
  $("userModalTitle").textContent = "User Details";

  show(modal);

  const [bp, weight, glucose] = await Promise.all([
    countByUser("bp_logs", userId),
    countByUser("weight_logs", userId),
    countByUser("glucose_logs", userId),
  ]);

  const status = normalizeUserStatus(u);
  body.innerHTML = `
    <div class="modal-body-grid">
      <div class="modal-field"><label>Full Name</label><div class="value">${escapeHtml(u.full_name || "N/A")}</div></div>
      <div class="modal-field"><label>Email</label><div class="value">${escapeHtml(u.email || "N/A")}</div></div>
      <div class="modal-field"><label>Role</label><div class="value"><span class="badge badge-${escapeHtml(u.role)}">${escapeHtml(u.role)}</span></div></div>
      <div class="modal-field"><label>Status</label><div class="value"><span class="badge badge-${escapeHtml(status)}">${escapeHtml(status.toUpperCase())}</span></div></div>
      <div class="modal-field"><label>User ID</label><div class="value"><small>${escapeHtml(u.id)}</small></div></div>
      <div class="modal-field"><label>Joined</label><div class="value">${u.created_at ? escapeHtml(formatDate(u.created_at)) : "N/A"}</div></div>
      <div class="modal-field"><label>BP Logs</label><div class="value">${bp} readings</div></div>
      <div class="modal-field"><label>Weight Logs</label><div class="value">${weight} readings</div></div>
      <div class="modal-field"><label>Glucose Logs</label><div class="value">${glucose} readings</div></div>
      <div class="modal-field"><label>Last Updated</label><div class="value">${u.updated_at ? escapeHtml(formatDateTime(u.updated_at)) : "N/A"}</div></div>
    </div>
  `;
}

function closeUserModal() {
  hide($("userModal"));
}

async function editUser(userId) {
  const u = state.allUsers.find((x) => x.id === userId);
  if (!u) return;

  const isSelf = state.currentAdminId && userId === state.currentAdminId;

  const modal = $("userModal");
  const body = $("userModalBody");
  $("userModalTitle").textContent = "Edit User";

  const status = normalizeUserStatus(u);

  body.innerHTML = `
    <form id="editUserForm">
      <div class="modal-body-grid">
        <div class="modal-field">
          <label>Full Name *</label>
          <input type="text" id="edit_full_name" value="${escapeHtml(u.full_name || "")}" required />
        </div>

        <div class="modal-field">
          <label>Email *</label>
          <input type="email" id="edit_email" value="${escapeHtml(u.email || "")}" required />
        </div>

        <div class="modal-field">
          <label>Role * ${isSelf ? '<small style="color:#e74c3c;">(Cannot change own role)</small>' : ""}</label>
          <select id="edit_role" ${isSelf ? "disabled" : ""} required>
            <option value="patient" ${u.role === "patient" ? "selected" : ""}>Patient</option>
            <option value="doctor" ${u.role === "doctor" ? "selected" : ""}>Doctor</option>
            <option value="admin" ${u.role === "admin" ? "selected" : ""}>Admin</option>
          </select>
        </div>

        <div class="modal-field">
          <label>Status * ${isSelf ? '<small style="color:#e74c3c;">(Cannot change own status)</small>' : ""}</label>
          <select id="edit_status" ${isSelf ? "disabled" : ""} required>
            <option value="active" ${status === "active" ? "selected" : ""}>Active</option>
            <option value="inactive" ${status === "inactive" ? "selected" : ""}>Inactive</option>
            <option value="suspended" ${status === "suspended" ? "selected" : ""}>Suspended</option>
          </select>
        </div>

        <div class="modal-field" style="grid-column: 1 / -1;">
          <label>Reason (for audit) *</label>
          <input type="text" id="edit_reason" placeholder="e.g., Updated email per user request" required />
        </div>
      </div>

      ${isSelf ? '<div style="background:#fff3cd;padding:10px;border-radius:4px;margin-top:12px;color:#856404;font-size:13px;">⚠️ Self-protection: You cannot change your own role/status.</div>' : ""}

      <div style="margin-top: 18px; display:flex; gap:10px; justify-content:flex-end;">
        <button type="button" class="btn btn-close" onclick="AdminApp.closeUserModal()">Cancel</button>
        <button type="submit" class="btn btn-activate">Save Changes</button>
      </div>
    </form>
  `;

  show(modal);

  qs("#editUserForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    await saveUserEdit(userId, isSelf);
  });
}

async function saveUserEdit(userId, isSelf) {
  const full_name = qs("#edit_full_name")?.value?.trim();
  const email = qs("#edit_email")?.value?.trim();
  const reason = qs("#edit_reason")?.value?.trim();

  const role = isSelf
    ? state.allUsers.find((u) => u.id === userId)?.role
    : qs("#edit_role")?.value;
  const status = isSelf
    ? normalizeUserStatus(state.allUsers.find((u) => u.id === userId))
    : qs("#edit_status")?.value;

  if (!full_name || !email || !role || !status || !reason) {
    alert("Please complete all required fields, including the reason.");
    return;
  }

  if (!confirm("Are you sure you want to update this user?")) return;

  try {
    // Update profiles
    const { error } = await supabaseClient
      .from("profiles")
      .update({
        full_name,
        email,
        role,
        status,
        updated_at: new Date().toISOString(),
      })
      .eq("id", userId);

    if (error) throw error;

    // Audit trail + activity feed
    await logAdminAction({
      module: "users",
      action: "updated",
      target_user_id: userId,
      description: `${state.currentAdminName} updated profile for ${full_name}.`,
      reason,
    });

    alert("✅ User updated successfully!");
    closeUserModal();
    await loadUsers();
    await loadActivityFeed();
  } catch (err) {
    console.error("saveUserEdit error:", err);
    alert(`❌ Failed to update user: ${err.message}`);
  }
}

async function changeUserStatus(userId, newStatus) {
  const u = state.allUsers.find((x) => x.id === userId);
  if (!u) return;

  const actionWord =
    newStatus === "suspended"
      ? "suspend"
      : newStatus === "inactive"
        ? "deactivate"
        : "activate";

  // Describe what will happen to the user for confirmation
  const consequenceMap = {
    suspended: "They will be immediately logged out and BLOCKED from logging in again.",
    inactive:  "They will be logged out on their next action (soft block).",
    active:    "Their access will be restored.",
  };

  const reason = prompt(`Reason to ${actionWord} this user (required for audit):`);
  if (!reason) return;

  if (!confirm(
    `Are you sure you want to ${actionWord} ${u.full_name || u.email}?\n\n${consequenceMap[newStatus]}`
  )) return;

  try {
    const { error } = await supabaseClient
      .from("profiles")
      .update({ status: newStatus, updated_at: new Date().toISOString() })
      .eq("id", userId);

    if (error) throw error;

    // SUSPEND: Hard block — attempt immediate session revocation
    if (newStatus === "suspended") {
      try {
        await supabaseClient.auth.admin.signOut(userId);
      } catch (_) {
        // Requires service role key — DB trigger handles it instead
      }
    }
    // INACTIVE (Deactivate): Soft block — session watcher will catch it within 60s
    // ACTIVE (Activate): No logout needed — restoring access

    await logAdminAction({
      module: "users",
      action: newStatus,
      target_user_id: userId,
      description: `${state.currentAdminName} ${actionWord}d ${u.full_name || u.email}.`,
      reason,
    });

    const resultMsg = {
      suspended: "✅ User suspended! They are now blocked from accessing the app.",
      inactive:  "✅ User deactivated. They will be logged out within 60 seconds.",
      active:    "✅ User activated! Their access has been restored.",
    };

    alert(resultMsg[newStatus]);
    await loadUsers();
    await loadActivityFeed();
  } catch (err) {
    console.error("changeUserStatus error:", err);
    alert(`❌ Failed to ${actionWord} user: ${err.message}`);
  }
}

async function archiveUser(userId) {
  const u = state.allUsers.find((x) => x.id === userId);
  if (!u) return;

  const reason = prompt("Reason to archive this user (required for audit):");
  if (!reason) return;

  if (
    !confirm(
      `Archive ${u.full_name || u.email}? This is a soft-delete and can be restored.`,
    )
  )
    return;

  try {
    const { error } = await supabaseClient
      .from("profiles")
      .update({
        deleted_at: new Date().toISOString(),
        status: "inactive",
        updated_at: new Date().toISOString(),
      })
      .eq("id", userId);

    if (error) throw error;

    // Force logout the archived user's active sessions
    try {
      await supabaseClient.auth.admin.signOut(userId);
    } catch (_) {
      // admin.signOut requires service role key — silently skip if unavailable
      // The deleted_at check on next page load will block them anyway
    }

    await logAdminAction({
      module: "users",
      action: "archived",
      target_user_id: userId,
      description: `${state.currentAdminName} archived ${u.full_name || u.email}.`,
      reason,
    });

    alert("✅ User archived. They are now blocked from accessing the app.");
    await loadUsers();
    await loadActivityFeed();
  } catch (err) {
    console.error("archiveUser error:", err);
    alert(`❌ Failed to archive user: ${err.message}`);
  }
}

async function restoreUser(userId) {
  const u = state.allUsers.find((x) => x.id === userId);
  if (!u) return;

  const reason = prompt("Reason to restore this user (required for audit):");
  if (!reason) return;

  if (!confirm(`Restore ${u.full_name || u.email} from archive?`)) return;

  try {
    const { error } = await supabaseClient
      .from("profiles")
      .update({
        deleted_at: null,
        status: "active",
        updated_at: new Date().toISOString(),
      })
      .eq("id", userId);

    if (error) throw error;

    await logAdminAction({
      module: "users",
      action: "restored",
      target_user_id: userId,
      description: `${state.currentAdminName} restored ${u.full_name || u.email} from archive.`,
      reason,
    });

    alert("✅ User restored.");
    await loadUsers();
    await loadActivityFeed();
  } catch (err) {
    console.error("restoreUser error:", err);
    alert(`❌ Failed to restore user: ${err.message}`);
  }
}

/* =========================
   9) CREATE USER
   ========================= */
function openCreateUserModal() {
  $("createUserForm")?.reset();
  show($("createUserModal"));
}

function closeCreateUserModal() {
  hide($("createUserModal"));
}

async function createUser(e) {
  e.preventDefault();

  const email = $("newUserEmail").value.trim();
  const password = $("newUserPassword").value;
  const full_name = $("newUserName").value.trim();
  const role = $("newUserRole").value;

  if (!email || !password || !full_name || !role) {
    alert("Please complete all fields.");
    return;
  }

  const reason = prompt("Reason to create this user (required for audit):");
  if (!reason) return;

  if (!confirm(`Create new ${role} user: ${email}?`)) return;

  try {
    /**
     * NOTE: auth.signUp() on the client will switch the active session to the newly
     * created user, logging the admin out. We capture the admin's session first
     * and restore it immediately after.
     */
    const { data: { session: adminSession } } = await supabaseClient.auth.getSession();

    const { data: signUpData, error: signUpError } =
      await supabaseClient.auth.signUp({
        email,
        password,
      });

    if (signUpError) throw signUpError;

    const newUserId = signUpData?.user?.id;
    if (!newUserId)
      throw new Error("Auth signup succeeded but user id was not returned.");

    // Immediately restore admin session so we don't get logged out
    if (adminSession) {
      await supabaseClient.auth.setSession({
        access_token: adminSession.access_token,
        refresh_token: adminSession.refresh_token,
      });
    }

    // Create profile row
    const { error: profileError } = await supabaseClient
      .from("profiles")
      .insert({
        id: newUserId,
        email,
        full_name,
        role,
        status: "active",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });

    if (profileError) throw profileError;

    await logAdminAction({
      module: "users",
      action: "created",
      target_user_id: newUserId,
      description: `${state.currentAdminName} created new ${role} account for ${email}.`,
      reason,
    });

    alert("✅ User created successfully!");
    closeCreateUserModal();
    await loadUsers();
    await loadActivityFeed();
  } catch (err) {
    console.error("createUser error:", err);
    alert(`❌ Failed to create user: ${err.message}`);
  }
}

/* =========================
   10) METRICS + HEALTH LOGS
   ========================= */
async function loadMetrics() {
  const usersCount = await getCount("profiles");
  const bpCount = await getCount("bp_logs");
  const weightCount = await getCount("weight_logs");
  const glucoseCount = await getCount("glucose_logs");

  $("count-users").textContent = usersCount;
  $("count-bp").textContent = bpCount;
  $("count-weight").textContent = weightCount;
  $("count-glucose").textContent = glucoseCount;
}

async function getCount(table) {
  const { count, error } = await supabaseClient
    .from(table)
    .select("*", { count: "exact", head: true });

  if (error) {
    console.warn("getCount error:", table, error);
    return 0;
  }
  return count || 0;
}

async function countByUser(table, userId) {
  const { count, error } = await supabaseClient
    .from(table)
    .select("*", { count: "exact", head: true })
    .eq("user_id", userId);

  if (error) return 0;
  return count || 0;
}

async function loadRecentLogs() {
  const tbody = $("recentLogsBody");
  if (!tbody) return;

  tbody.innerHTML =
    '<tr><td colspan="5" class="empty-state">Loading...</td></tr>';

  const logType = $("logTypeFilter")?.value || "all";

  try {
    const { data: profiles } = await supabaseClient
      .from("profiles")
      .select("id, full_name, email");

    const profileMap = {};
    (profiles || []).forEach(
      (p) => (profileMap[p.id] = p.full_name || p.email || "Unknown"),
    );

    const allLogs = [];

    if (logType === "all" || logType === "bp") {
      const { data } = await supabaseClient
        .from("bp_logs")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(10);
      (data || []).forEach((log) =>
        allLogs.push({
          ...log,
          type: "BP",
          reading: `${log.systolic}/${log.diastolic} mmHg`,
          user_name: profileMap[log.user_id] || "Unknown User",
        }),
      );
    }

    if (logType === "all" || logType === "weight") {
      const { data } = await supabaseClient
        .from("weight_logs")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(10);
      (data || []).forEach((log) =>
        allLogs.push({
          ...log,
          type: "Weight",
          reading: `${log.weight} kg`,
          user_name: profileMap[log.user_id] || "Unknown User",
        }),
      );
    }

    if (logType === "all" || logType === "glucose") {
      const { data } = await supabaseClient
        .from("glucose_logs")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(10);
      (data || []).forEach((log) =>
        allLogs.push({
          ...log,
          type: "Glucose",
          reading: `${log.glucose_level} mg/dL`,
          user_name: profileMap[log.user_id] || "Unknown User",
        }),
      );
    }

    allLogs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    tbody.innerHTML = "";
    if (!allLogs.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-state">No recent logs found.</td></tr>';
      return;
    }

    allLogs.slice(0, 20).forEach((log) => {
      const status = getHealthStatus(log);
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><span class="badge badge-${log.type.toLowerCase()}">${log.type}</span></td>
        <td>${escapeHtml(log.user_name)}</td>
        <td><strong>${escapeHtml(log.reading)}</strong></td>
        <td><small>${escapeHtml(formatDateTime(log.created_at))}</small></td>
        <td><span class="badge ${status.class}">${status.text}</span></td>
      `;
      tbody.appendChild(row);
    });
  } catch (err) {
    console.error("loadRecentLogs error:", err);
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state" style="color:red">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function getHealthStatus(log) {
  if (log.type === "BP") {
    if (log.systolic > 140 || log.diastolic > 90)
      return { class: "badge-high", text: "High" };
    if (log.systolic < 90 || log.diastolic < 60)
      return { class: "badge-low", text: "Low" };
    return { class: "badge-normal", text: "Normal" };
  }
  if (log.type === "Glucose") {
    if (log.glucose_level > 140) return { class: "badge-high", text: "High" };
    if (log.glucose_level < 70) return { class: "badge-low", text: "Low" };
    return { class: "badge-normal", text: "Normal" };
  }
  return { class: "badge-normal", text: "Logged" };
}

/* =========================
   11) ACTIVITY FEED (Unified)
   ========================= */
function activityIcon(module, action) {
  if (module === "users") {
    if (action === "created") return "👤";
    if (action === "updated") return "✏️";
    if (action === "suspended") return "⛔";
    if (action === "inactive") return "⏸️";
    if (action === "active") return "✅";
    if (action === "archived") return "🗄️";
    if (action === "restored") return "♻️";
    return "👥";
  }
  if (module === "tickets") {
    if (action === "created") return "🎫";
    if (action === "progress") return "🟡";
    if (action === "resolved") return "🟢";
    if (action === "reopened") return "🔁";
    if (action === "replied") return "💬";
    return "🎫";
  }
  if (module === "doctors") {
    if (action === "assigned_patient") return "🩺";
    if (action === "unassigned_patient") return "➖";
    if (action === "unassigned_all") return "🧹";
    return "🩺";
  }
  return "🔔";
}

async function loadActivityFeed() {
  const container = $("activityLog");
  if (!container) return;

  try {
    // Build a profile map so we can display names instead of emails everywhere
    const { data: profiles, error: pe } = await supabaseClient
      .from("profiles")
      .select("id, full_name, email, deleted_at");

    if (pe) throw pe;

    const idToName = {};
    const emailToName = {};
    (profiles || []).forEach((p) => {
      const name = p.full_name || p.email || "Unknown";
      idToName[p.id] = { name, deleted_at: p.deleted_at, email: p.email };
      if (p.email) emailToName[p.email] = name;
    });

    // Platform activity (admin actions, assignments, ticket updates, etc.)
    const { data: act, error } = await supabaseClient
      .from("platform_activity")
      .select(
        "id, module, action, description, created_at, actor_id, target_user_id",
      )
      .order("created_at", { ascending: false })
      .limit(50);

    if (error) throw error;

    const platformItems = (act || [])
      .filter((a) => {
        // Hide activity for archived users (either actor or target)
        const actor = a.actor_id ? idToName[a.actor_id] : null;
        const target = a.target_user_id ? idToName[a.target_user_id] : null;
        if (actor?.deleted_at) return false;
        if (target?.deleted_at) return false;
        return true;
      })
      .map((a) => {
        // Replace any known emails in description with full names
        let desc = a.description || "";
        Object.keys(emailToName).forEach((em) => {
          // Replace all occurrences safely
          desc = desc.split(em).join(emailToName[em]);
        });
        return {
          kind: "platform",
          module: a.module,
          action: a.action,
          created_at: a.created_at,
          description: desc,
        };
      });

    // Health logs should also appear in the activity feed
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);

    const [bpRes, weightRes, glucoseRes] = await Promise.all([
      supabaseClient
        .from("bp_logs")
        .select("user_id, systolic, diastolic, created_at")
        .gte("created_at", weekAgo.toISOString())
        .order("created_at", { ascending: false })
        .limit(20),
      supabaseClient
        .from("weight_logs")
        .select("user_id, weight, created_at")
        .gte("created_at", weekAgo.toISOString())
        .order("created_at", { ascending: false })
        .limit(20),
      supabaseClient
        .from("glucose_logs")
        .select("user_id, glucose_level, created_at")
        .gte("created_at", weekAgo.toISOString())
        .order("created_at", { ascending: false })
        .limit(20),
    ]);

    const healthItems = [];

    (bpRes.data || []).forEach((x) => {
      const user = idToName[x.user_id];
      if (user?.deleted_at) return; // hide archived users
      const name = user?.name || "Unknown User";
      if (x.systolic == null || x.diastolic == null) return;
      healthItems.push({
        kind: "health",
        module: "health",
        action: "bp",
        created_at: x.created_at,
        description: `${name} logged BP ${x.systolic}/${x.diastolic} mmHg`,
      });
    });

    (weightRes.data || []).forEach((x) => {
      const user = idToName[x.user_id];
      if (user?.deleted_at) return;
      const name = user?.name || "Unknown User";
      if (x.weight == null) return;
      healthItems.push({
        kind: "health",
        module: "health",
        action: "weight",
        created_at: x.created_at,
        description: `${name} logged weight ${x.weight} kg`,
      });
    });

    (glucoseRes.data || []).forEach((x) => {
      const user = idToName[x.user_id];
      if (user?.deleted_at) return;
      const name = user?.name || "Unknown User";
      if (x.glucose_level == null) return;
      healthItems.push({
        kind: "health",
        module: "health",
        action: "glucose",
        created_at: x.created_at,
        description: `${name} logged glucose ${x.glucose_level} mg/dL`,
      });
    });

    // Merge + sort by time
    const merged = [...platformItems, ...healthItems]
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, 20);

    container.innerHTML = "";

    if (!merged.length) {
      container.innerHTML =
        '<div class="activity-item"><div class="description">No recent activity</div></div>';
      return;
    }

    merged.forEach((a) => {
      const item = document.createElement("div");
      item.className = "activity-item";
      const icon =
        a.kind === "health"
          ? a.action === "bp"
            ? "🩸"
            : a.action === "weight"
              ? "⚖️"
              : "🧪"
          : activityIcon(a.module, a.action);

      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div class="time">⏰ ${escapeHtml(timeAgo(a.created_at))}</div>
            <div class="description">${icon} ${escapeHtml(a.description || "")}</div>
          </div>
        </div>
      `;
      container.appendChild(item);
    });
  } catch (err) {
    console.error("loadActivityFeed error:", err);
    container.innerHTML =
      '<div class="activity-item"><div class="description">Error loading activity.</div></div>';
  }
}

async function logAdminAction({
  module,
  action,
  target_user_id = null,
  description,
  reason,
}) {
  // Write both admin audit log (more detailed) and platform activity (user-facing feed)
  const nowIso = new Date().toISOString();

  const auditPayload = {
    admin_id: state.currentAdminId,
    target_user_id,
    module,
    action,
    reason,
    created_at: nowIso,
  };

  const activityPayload = {
    actor_id: state.currentAdminId,
    target_user_id,
    module,
    action,
    description,
    created_at: nowIso,
  };

  // Best effort (don’t block UI if one fails, but log it)
  const [a1, a2] = await Promise.all([
    supabaseClient.from("admin_audit_log").insert(auditPayload),
    supabaseClient.from("platform_activity").insert(activityPayload),
  ]);

  if (a1.error) console.warn("admin_audit_log insert failed:", a1.error);
  if (a2.error) console.warn("platform_activity insert failed:", a2.error);
}

/* =========================
   12) WEEKLY CHART (Multi-type)
   ========================= */
async function loadWeeklyChart() {
  const chart = $("weeklyChart");
  if (!chart) return;

  chart.innerHTML = `<div class="chart-empty-msg">⏳ Loading chart...</div>`;

  try {
    const today = new Date();
    // Build array of last 7 days starting from Monday of this week
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      d.setHours(0, 0, 0, 0);
      days.push(d);
    }
    const weekStart = days[0].toISOString();

    // Fetch all three data sources in parallel
    const [bpRes, weightRes, glucoseRes, usersRes, ticketsRes] = await Promise.all([
      supabaseClient.from("bp_logs").select("created_at").gte("created_at", weekStart),
      supabaseClient.from("weight_logs").select("created_at").gte("created_at", weekStart),
      supabaseClient.from("glucose_logs").select("created_at").gte("created_at", weekStart),
      supabaseClient.from("profiles").select("created_at").gte("created_at", weekStart),
      supabaseClient.from("tickets").select("created_at").gte("created_at", weekStart),
    ]);

    // Helper: count rows per day-of-week index (0=Mon ... 6=Sun relative to days[])
    function countPerDay(rows) {
      const counts = Array(7).fill(0);
      (rows || []).forEach((r) => {
        const d = new Date(r.created_at);
        d.setHours(0, 0, 0, 0);
        const idx = days.findIndex((day) => day.getTime() === d.getTime());
        if (idx !== -1) counts[idx]++;
      });
      return counts;
    }

    const healthCounts = countPerDay([
      ...(bpRes.data || []),
      ...(weightRes.data || []),
      ...(glucoseRes.data || []),
    ]);
    const userCounts  = countPerDay(usersRes.data || []);
    const ticketCounts = countPerDay(ticketsRes.data || []);

    // Overall max for scaling (use at least 1 to avoid division by zero)
    const allValues = [...healthCounts, ...userCounts, ...ticketCounts];
    const maxVal = Math.max(...allValues, 1);

    const dayNames = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const BAR_MAX_H = 160; // px

    const hasAnyData = allValues.some((v) => v > 0);

    if (!hasAnyData) {
      chart.innerHTML = `<div class="chart-empty-msg">No activity recorded this week yet.</div>`;
      const totalRow = $("chartTotalRow");
      if (totalRow) totalRow.innerHTML = "";
      return;
    }

    chart.innerHTML = days.map((_, i) => {
      const h  = healthCounts[i];
      const u  = userCounts[i];
      const t  = ticketCounts[i];
      const total = h + u + t;

      // Heights in px — 0 means no bar rendered at all
      const hh = h > 0 ? Math.max(6, Math.round((h / maxVal) * BAR_MAX_H)) : 0;
      const uh = u > 0 ? Math.max(6, Math.round((u / maxVal) * BAR_MAX_H)) : 0;
      const th = t > 0 ? Math.max(6, Math.round((t / maxVal) * BAR_MAX_H)) : 0;

      const healthBar  = h > 0 ? `<div class="day-bar" style="height:${hh}px;background:#2daa2d;" title="Health logs: ${h}"></div>` : `<div class="day-bar" style="height:0;background:transparent;"></div>`;
      const userBar    = u > 0 ? `<div class="day-bar" style="height:${uh}px;background:#3b82f6;" title="New users: ${u}"></div>` : `<div class="day-bar" style="height:0;background:transparent;"></div>`;
      const ticketBar  = t > 0 ? `<div class="day-bar" style="height:${th}px;background:#f59e0b;" title="Tickets: ${t}"></div>` : `<div class="day-bar" style="height:0;background:transparent;"></div>`;

      return `
        <div class="day-group">
          <div class="day-bars">
            ${healthBar}${userBar}${ticketBar}
          </div>
          <div class="day-label">${dayNames[i]}</div>
          <div class="day-total">${total > 0 ? total : ""}</div>
        </div>
      `;
    }).join("");

  } catch (err) {
    console.error("loadWeeklyChart error:", err);
    chart.innerHTML = `<div class="chart-empty-msg">Error loading chart data.</div>`;
  }
}

/* =========================
   13) SUPPORT TICKETS
   ========================= */
async function loadTickets() {
  const tbody = $("ticketTableBody");
  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="7" class="empty-state">Refreshing tickets...</td>
    </tr>
  `;

  const { data, error } = await supabaseClient
    .from("tickets")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="empty-state" style="color:red">Error loading tickets</td></tr>';
    return;
  }

  state.allTickets = data || [];
  applyTicketFilters();
  updateTicketStats(state.allTickets);
}

function applyTicketFilters() {
  const term = $("ticketSearch")?.value?.trim().toLowerCase() || "";
  const priority = $("priorityFilter")?.value || "all";
  const status = $("ticketStatusFilter")?.value || "all";

  let filtered = [...state.allTickets];

  if (term) {
    filtered = filtered.filter(
      (t) =>
        (t.subject || "").toLowerCase().includes(term) ||
        (t.user || t.user_name || "").toLowerCase().includes(term) ||
        (t.id || "").toLowerCase().includes(term),
    );
  }
  if (priority !== "all")
    filtered = filtered.filter((t) => t.priority === priority);
  if (status !== "all") filtered = filtered.filter((t) => t.status === status);

  renderTickets(filtered);
}

function updateTicketStats(tickets) {
  const open = tickets.filter((t) => t.status === "open").length;
  const progress = tickets.filter((t) => t.status === "progress").length;
  const resolved = tickets.filter((t) => t.status === "resolved").length;

  $("openTickets").textContent = String(open);
  $("progressTickets").textContent = String(progress);
  $("resolvedTickets").textContent = String(resolved);

  // Avg response: created_at -> updated_at for non-open
  const responded = tickets.filter(
    (t) => t.status !== "open" && t.created_at && t.updated_at,
  );
  if (!responded.length) {
    $("avgResponse").textContent = "N/A";
    return;
  }

  const avgMs =
    responded.reduce(
      (sum, t) => sum + (new Date(t.updated_at) - new Date(t.created_at)),
      0,
    ) / responded.length;
  const hours = avgMs / (1000 * 60 * 60);

  if (hours < 1)
    $("avgResponse").textContent = `${Math.max(1, Math.round(hours * 60))}m`;
  else if (hours < 24) $("avgResponse").textContent = `${hours.toFixed(1)}h`;
  else $("avgResponse").textContent = `${Math.round(hours / 24)}d`;
}

function renderTickets(tickets) {
  const tbody = $("ticketTableBody");
  tbody.innerHTML = "";

  if (!tickets.length) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="empty-state">No tickets found.</td></tr>';
    return;
  }

  const priorityOrder = { high: 1, medium: 2, low: 3 };
  const sorted = [...tickets].sort((a, b) => {
    const p =
      (priorityOrder[a.priority] || 9) - (priorityOrder[b.priority] || 9);
    if (p !== 0) return p;
    return new Date(b.created_at) - new Date(a.created_at);
  });

  sorted.forEach((t) => {
    const row = document.createElement("tr");
    row.dataset.ticketId = t.id;
    row.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      selectTicketRow(t.id);
    });

    const borderColor =
      t.priority === "high"
        ? "#e74c3c"
        : t.priority === "medium"
          ? "#f39c12"
          : "#27ae60";

    row.innerHTML = `
<td style="border-left: 4px solid ${borderColor};"><strong>${escapeHtml((t.id || "").substring(0, 8))}</strong></td>
      <td>${escapeHtml(t.user || t.user_name || "Unknown")}</td>
      <td>${escapeHtml(t.subject || "")}</td>
      <td><select class="priority-select"
        onchange="updateTicketPriority('${t.id}', this.value)">
  <option value="low" ${t.priority === "low" ? "selected" : ""}>Low</option>
  <option value="medium" ${t.priority === "medium" ? "selected" : ""}>Medium</option>
  <option value="high" ${t.priority === "high" ? "selected" : ""}>High</option>
</select></td>
      <td><span class="badge badge-${escapeHtml(t.status)}">${escapeHtml(t.status === "progress" ? "IN PROGRESS" : (t.status || "").toUpperCase())}</span></td>
      <td><small>${escapeHtml(formatDateTime(t.created_at))}</small></td>
      <td>
        <div class="action-buttons">
          <button class="btn btn-view" type="button" onclick="AdminApp.viewTicket('${t.id}')">View</button>
          <button class="btn btn-edit" type="button" onclick="AdminApp.updateTicketStatus('${t.id}','${nextTicketStatus(t.status)}')">${ticketActionLabel(t.status)}</button>
        </div>
      </td>
    `;
    tbody.appendChild(row);
  });
  syncSelectedTicketStyles();
}

function nextTicketStatus(status) {
  if (status === "open") return "progress";
  if (status === "progress") return "resolved";
  if (status === "resolved") return "open";
  return "open";
}

function ticketActionLabel(status) {
  if (status === "open") return "In Progress";
  if (status === "progress") return "Resolve";
  if (status === "resolved") return "Reopen";
  return "Update";
}

async function updateTicketStatus(ticketId, newStatus) {
  const ticket = state.allTickets.find((t) => t.id === ticketId);
  if (!ticket) return;

  const reason = prompt(
    `Reason to set ticket to "${newStatus}" (for audit/activity):`,
  );
  if (!reason) return;

  if (!confirm(`Update ticket ${ticketId.substring(0, 8)} to ${newStatus}?`))
    return;

  try {
    const { error } = await supabaseClient
      .from("tickets")
      .update({ status: newStatus, updated_at: new Date().toISOString() })
      .eq("id", ticketId);

    if (error) throw error;

    await logAdminAction({
      module: "tickets",
      action: newStatus === "open" ? "reopened" : newStatus,
      target_user_id: null,
      description: `${state.currentAdminName} moved ticket #${ticketId.substring(0, 8)} to ${newStatus === "open" ? "re-opened" : newStatus}.`,
      reason,
    });

    await loadTickets();
    await loadActivityFeed();
  } catch (err) {
    console.error("updateTicketStatus error:", err);
    alert(`❌ Failed to update ticket: ${err.message}`);
  }
}

async function viewTicket(ticketId) {
  const ticket = state.allTickets.find((t) => t.id === ticketId);
  if (!ticket) return;

  show($("ticketPanel"));
  $("ticketThread").innerHTML = `
    <div class="activity-item">
      <div class="time">Created: ${escapeHtml(formatDateTime(ticket.created_at))}</div>
      <div class="description"><strong>${escapeHtml(ticket.subject || "")}</strong></div>
      <div class="description">${escapeHtml(ticket.description || "")}</div>
    </div>
  `;

  $("ticketReply").value = "";
  $("ticketPanel").dataset.ticketId = ticketId;
}

function closeTicketPanel() {
  hide($("ticketPanel"));
  $("ticketPanel").dataset.ticketId = "";
}

async function sendTicketReply() {
  const ticketId = $("ticketPanel")?.dataset?.ticketId;
  if (!ticketId) return;

  const message = $("ticketReply").value.trim();
  if (!message) {
    alert("Please type a reply.");
    return;
  }

  const reason = "Ticket reply sent"; // still logged
  try {
    // Try to store the reply in ticket_replies table if it exists,
    // otherwise just update the ticket's updated_at as a lightweight fallback
    const { error: replyError } = await supabaseClient
      .from("ticket_replies")
      .insert({
        ticket_id: ticketId,
        admin_id: state.currentAdminId,
        message,
        created_at: new Date().toISOString(),
      });

    // Fallback: always bump updated_at on the ticket regardless
    await supabaseClient
      .from("tickets")
      .update({ updated_at: new Date().toISOString() })
      .eq("id", ticketId);

    if (replyError) {
      // ticket_replies table may not exist yet — that's ok, reply still shows in UI
      console.warn("ticket_replies insert failed (table may not exist):", replyError.message);
    }

    await logAdminAction({
      module: "tickets",
      action: "replied",
      target_user_id: null,
      description: `${state.currentAdminName} replied on ticket #${ticketId.substring(0, 8)}.`,
      reason,
    });

    const item = document.createElement("div");
    item.className = "activity-item";
    item.innerHTML = `
      <div class="time">⏰ ${escapeHtml(timeAgo(new Date().toISOString()))}</div>
      <div class="description">💬 Admin: ${escapeHtml(message)}</div>
    `;
    $("ticketThread").appendChild(item);
    $("ticketReply").value = "";

    await loadActivityFeed();
  } catch (err) {
    console.error("sendTicketReply error:", err);
    alert(`❌ Failed to send reply: ${err.message}`);
  }
}

/* =========================
   14) DOCTOR WORKFLOWS
   ========================= */
async function loadDoctors() {
  const container = $("doctorList");
  if (!container) return;
  container.textContent = "Loading...";

  const { data, error } = await supabaseClient
    .from("profiles")
    .select("id, full_name, email, role, status, deleted_at")
    .eq("role", "doctor")
    .order("full_name", { ascending: true });

  if (error) {
    container.textContent = "Error loading doctors";
    return;
  }

  state.allDoctors = (data || []).filter((d) => !d.deleted_at);
  filterDoctors();
}

function filterDoctors() {
  const term = $("doctorSearch")?.value?.trim().toLowerCase() || "";
  let list = [...state.allDoctors];
  if (term) {
    list = list.filter(
      (d) =>
        (d.full_name || "").toLowerCase().includes(term) ||
        (d.email || "").toLowerCase().includes(term),
    );
  }
  renderDoctorList(list);
}

function renderDoctorList(doctors) {
  const container = $("doctorList");
  container.innerHTML = "";

  if (!doctors.length) {
    container.textContent = "No doctors found.";
    return;
  }

  doctors.forEach((d) => {
    const item = document.createElement("div");
    item.className = "list-item";
    const status = normalizeUserStatus(d);

    item.innerHTML = `
      <div class="meta">
        <div class="title">${escapeHtml(d.full_name || "Doctor")}</div>
        <div class="sub">${escapeHtml(d.email || "")} • ${escapeHtml(status)}</div>
      </div>
      <div class="right">
        <button class="btn btn-view" type="button">Select</button>
      </div>
    `;

    item
      .querySelector("button")
      ?.addEventListener("click", () => selectDoctor(d));
    container.appendChild(item);
  });
}

async function selectDoctor(doctor) {
  state.selectedDoctorId = doctor.id;
  state.selectedDoctorName = doctor.full_name || "Doctor";
  state.selectedDoctorEmail = doctor.email || "";

  $("openAssignPatientBtn").disabled = false;
  $("unassignAllBtn").disabled = false;

  await loadAssignmentsForDoctor(doctor.id);
}

async function loadAssignmentsForDoctor(doctorId) {
  const list = $("patientList");
  list.textContent = "Loading assignments...";

  const { data, error } = await supabaseClient
    .from("doctor_patient_assignments")
    .select("id, doctor_id, patient_id, assigned_at")
    .eq("doctor_id", doctorId)
    .order("assigned_at", { ascending: false });

  if (error) {
    list.textContent = "Error loading assigned patients";
    return;
  }

  state.assignments = data || [];

  // Resolve patient profiles
  const patientIds = state.assignments.map((a) => a.patient_id);
  if (!patientIds.length) {
    list.textContent = "No patients assigned. Use “Assign Patient”.";
    return;
  }

  const { data: patients, error: pe } = await supabaseClient
    .from("profiles")
    .select("id, full_name, email, status, deleted_at")
    .in("id", patientIds);

  if (pe) {
    list.textContent = "Error resolving patient profiles";
    return;
  }

  const patientMap = {};
  (patients || []).forEach((p) => (patientMap[p.id] = p));

  renderAssignedPatients(patientMap);
}

function renderAssignedPatients(patientMap) {
  const list = $("patientList");
  list.innerHTML = "";

  const assignments = state.assignments;

  if (!assignments.length) {
    list.textContent = "No patients assigned. Use “Assign Patient”.";
    return;
  }

  assignments.forEach((a) => {
    const p = patientMap[a.patient_id];
    const displayName = p?.full_name || p?.email || a.patient_id;
    const status = p ? normalizeUserStatus(p) : "unknown";

    const item = document.createElement("div");
    item.className = "list-item";
    item.innerHTML = `
      <div class="meta">
        <div class="title">${escapeHtml(displayName)}</div>
        <div class="sub">${escapeHtml(p?.email || "")} • ${escapeHtml(status)} • Assigned ${escapeHtml(formatDateTime(a.assigned_at))}</div>
      </div>
      <div class="right">
        <button class="btn btn-inactive" type="button">Unassign</button>
      </div>
    `;

    item
      .querySelector("button")
      ?.addEventListener("click", () => unassignPatient(a.id, a.patient_id));
    list.appendChild(item);
  });
}

function openAssignPatientModal() {
  if (!state.selectedDoctorId) {
    alert("Select a doctor first.");
    return;
  }
  show($("assignPatientModal"));
  loadPatientPicker();
}

function closeAssignPatientModal() {
  hide($("assignPatientModal"));
}

async function loadPatientPicker() {
  const box = $("patientPickerList");
  box.textContent = "Loading...";

  // Patients not archived + role=patient
  const { data, error } = await supabaseClient
    .from("profiles")
    .select("id, full_name, email, role, status, deleted_at")
    .eq("role", "patient")
    .order("full_name", { ascending: true });

  if (error) {
    box.textContent = "Error loading patients";
    return;
  }

  // Exclude archived
  const patients = (data || []).filter((p) => !p.deleted_at);

  // Exclude already assigned to this doctor
  const assignedIds = new Set(state.assignments.map((a) => a.patient_id));
  state.patientPicker = patients.filter((p) => !assignedIds.has(p.id));

  renderPatientPicker();
}

function renderPatientPicker() {
  const box = $("patientPickerList");
  const term = $("patientSearch")?.value?.trim().toLowerCase() || "";

  let list = [...state.patientPicker];
  if (term) {
    list = list.filter(
      (p) =>
        (p.full_name || "").toLowerCase().includes(term) ||
        (p.email || "").toLowerCase().includes(term),
    );
  }

  box.innerHTML = "";

  if (!list.length) {
    box.textContent =
      "No available patients found (or all patients already assigned).";
    return;
  }

  list.slice(0, 200).forEach((p) => {
    const item = document.createElement("div");
    item.className = "list-item";
    const status = normalizeUserStatus(p);

    item.innerHTML = `
      <div class="meta">
        <div class="title">${escapeHtml(p.full_name || "Patient")}</div>
        <div class="sub">${escapeHtml(p.email || "")} • ${escapeHtml(status)}</div>
      </div>
      <div class="right">
        <button class="btn btn-activate" type="button">Assign</button>
      </div>
    `;

    item
      .querySelector("button")
      ?.addEventListener("click", () => assignPatientToDoctor(p));
    box.appendChild(item);
  });
}

async function assignPatientToDoctor(patient) {
  const doctorId = state.selectedDoctorId;
  if (!doctorId) return;

  const reason = prompt("Reason to assign this patient (required for audit):");
  if (!reason) return;

  if (
    !confirm(
      `Assign ${patient.full_name || patient.email} to ${state.selectedDoctorName}?`,
    )
  )
    return;

  try {
    const { error } = await supabaseClient
      .from("doctor_patient_assignments")
      .insert({
        doctor_id: doctorId,
        patient_id: patient.id,
        assigned_by: state.currentAdminId,
        assigned_at: new Date().toISOString(),
      });

    if (error) throw error;

    await logAdminAction({
      module: "doctors",
      action: "assigned_patient",
      target_user_id: doctorId,
      description: `${state.currentAdminName} assigned ${patient.full_name || patient.email} to Dr. ${state.selectedDoctorName || state.selectedDoctorEmail}.`,
      reason,
    });

    await loadAssignmentsForDoctor(doctorId);
    await loadActivityFeed();
    await loadPatientPicker();
  } catch (err) {
    console.error("assignPatientToDoctor error:", err);
    alert(`❌ Failed to assign patient: ${err.message}`);
  }
}

async function unassignPatient(assignmentId, patientId) {
  const reason = prompt(
    "Reason to unassign this patient (required for audit):",
  );
  if (!reason) return;

  if (!confirm("Unassign this patient from the selected doctor?")) return;

  try {
    const { error } = await supabaseClient
      .from("doctor_patient_assignments")
      .delete()
      .eq("id", assignmentId);

    if (error) throw error;

    await logAdminAction({
      module: "doctors",
      action: "unassigned_patient",
      target_user_id: state.selectedDoctorId,
      description: `${state.currentAdminName} unassigned a patient from Dr. ${state.selectedDoctorName || state.selectedDoctorEmail}.`,
      reason,
    });

    await loadAssignmentsForDoctor(state.selectedDoctorId);
    await loadActivityFeed();
  } catch (err) {
    console.error("unassignPatient error:", err);
    alert(`❌ Failed to unassign: ${err.message}`);
  }
}

async function unassignAllFromDoctor() {
  if (!state.selectedDoctorId) return;

  const reason = prompt(
    "Reason to unassign ALL patients (required for audit):",
  );
  if (!reason) return;

  if (!confirm(`Unassign ALL patients from ${state.selectedDoctorName}?`))
    return;

  try {
    const { error } = await supabaseClient
      .from("doctor_patient_assignments")
      .delete()
      .eq("doctor_id", state.selectedDoctorId);

    if (error) throw error;

    await logAdminAction({
      module: "doctors",
      action: "unassigned_all",
      target_user_id: state.selectedDoctorId,
      description: `${state.currentAdminName} unassigned all patients from Dr. ${state.selectedDoctorName || state.selectedDoctorEmail}.`,
      reason,
    });

    await loadAssignmentsForDoctor(state.selectedDoctorId);
    await loadActivityFeed();
  } catch (err) {
    console.error("unassignAllFromDoctor error:", err);
    alert(`❌ Failed to unassign all: ${err.message}`);
  }
}

/* =========================
   15) REALTIME
   ========================= */
function setupRealtime() {
  // Activity feed updates
  supabaseClient
    .channel("realtime-admin-dashboard")
    .on(
      "postgres_changes",
      { event: "*", schema: "public", table: "platform_activity" },
      () => {
        // Keep activity feed fresh
        loadActivityFeed();
      },
    )
    .on(
      "postgres_changes",
      { event: "*", schema: "public", table: "profiles" },
      () => {
        // Refresh users list when profiles change
        loadUsers();
        loadMetrics();
      },
    )
    .on(
      "postgres_changes",
      { event: "*", schema: "public", table: "tickets" },
      () => {
        loadTickets();
      },
    )
    .on(
      "postgres_changes",
      { event: "*", schema: "public", table: "doctor_patient_assignments" },
      (payload) => {
        // If viewing a doctor, refresh assignment list
        if (state.selectedDoctorId) {
          loadAssignmentsForDoctor(state.selectedDoctorId);
        }
      },
    )
    .subscribe((status) => {
      if (status !== "SUBSCRIBED") {
        console.warn("Realtime status:", status);
      }
    });
}

/* =========================
   16) GLOBAL EXPORT (for inline onclick)
   ========================= */
window.AdminApp = {
  viewUser,
  editUser,
  closeUserModal,
  changeUserStatus,
  archiveUser,
  restoreUser,
  viewTicket,
  updateTicketStatus,
};

/* =========================
   Init
   ========================= */
document.addEventListener("DOMContentLoaded", bootstrap);

async function updateTicketPriority(ticketId, newPriority) {
  try {
    const { error } = await supabaseClient
      .from("tickets")
      .update({ priority: newPriority })
      .eq("id", ticketId);

    if (error) throw error;

    await supabaseClient.from("platform_activity").insert({
      module: "tickets",
      action: "priority_change",
      actor_id: state.currentAdminId || null,
      target_user_id: null,
      description: `${state.currentAdminName} changed ticket #${ticketId.substring(0, 8)} priority to ${newPriority.toUpperCase()}.`,
      created_at: new Date().toISOString(),
    });

    await loadTickets();
    await loadActivityFeed();
  } catch (err) {
    console.error("Priority update failed:", err);
  }
}