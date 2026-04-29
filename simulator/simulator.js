/* ===================================================================
   Forward-Secure Signatures — Animation Simulator
   =================================================================== */

// ── Palette ──
const C = {
  bg:      '#0f1117', surface: '#1a1d27', border: '#2a2d3a',
  text:    '#e2e4ea', muted:   '#8b8fa3', accent: '#6c8cff',
  green:   '#34d399', red:     '#f87171', orange: '#fbbf24',
  cyan:    '#22d3ee', pink:    '#f472b6', deleted:'#dc2626',
  accent2: '#a78bfa',
};

// ── Technical Mode Toggle ──
let technicalMode = false;

function toggleTechnicalMode() {
  technicalMode = !technicalMode;
  // Update all toggle switch visuals
  document.querySelectorAll('.mode-toggle').forEach(toggle => {
    const labels = toggle.querySelectorAll('.toggle-label');
    if (technicalMode) {
      labels[0].classList.remove('toggle-active');
      labels[1].classList.add('toggle-active');
    } else {
      labels[0].classList.add('toggle-active');
      labels[1].classList.remove('toggle-active');
    }
  });
  // Re-render the active tab
  const activePanel = document.querySelector('.panel.active');
  if (activePanel) {
    const id = activePanel.id;
    if (id === 'panel-sum') sumUpdateUI();
    else if (id === 'panel-product') prodUpdateUI();
    else if (id === 'panel-mmm') mmmUpdateUI();
  }
}

// ── Tab switching ──
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
  });
});

// ── Utility ──
function roundRect(ctx, x, y, w, h, r, fill, stroke) {
  ctx.beginPath();
  ctx.moveTo(x+r, y);
  ctx.lineTo(x+w-r, y);
  ctx.quadraticCurveTo(x+w, y, x+w, y+r);
  ctx.lineTo(x+w, y+h-r);
  ctx.quadraticCurveTo(x+w, y+h, x+w-r, y+h);
  ctx.lineTo(x+r, y+h);
  ctx.quadraticCurveTo(x, y+h, x, y+h-r);
  ctx.lineTo(x, y+r);
  ctx.quadraticCurveTo(x, y, x+r, y);
  ctx.closePath();
  if (fill)   { ctx.fillStyle = fill; ctx.fill(); }
  if (stroke) { ctx.strokeStyle = stroke; ctx.lineWidth = 1.5; ctx.stroke(); }
}

function drawArrow(ctx, x1, y1, x2, y2, color) {
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
  const a = Math.atan2(y2-y1, x2-x1), s = 8;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.moveTo(x2, y2);
  ctx.lineTo(x2 - s*Math.cos(a - .4), y2 - s*Math.sin(a - .4));
  ctx.lineTo(x2 - s*Math.cos(a + .4), y2 - s*Math.sin(a + .4));
  ctx.fill();
}

function drawDashedLine(ctx, x1, y1, x2, y2, color) {
  ctx.strokeStyle = color; ctx.lineWidth = 1.5;
  ctx.setLineDash([5,4]);
  ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
  ctx.setLineDash([]);
}

/* ===================================================================
   SUM COMPOSITION ANIMATION
   Sum(A, B, C, D) as a depth-2 binary tree → 4 time periods
   =================================================================== */

const SUM_STEPS = [
  {
    title: 'Hiring the Officers',
    text: 'SecureBank hires four weekly signing officers (A, B, C, D). Each gets a unique digital seal. A master registry links all four seals under one bank identity.',
    titleTech: 'Key Generation',
    textTech: 'We start with a <span class="c-orange">master seed</span> and split it using a PRG (pseudorandom generator) into seeds for each leaf. Each leaf is an independent ML-DSA key pair. The <span class="c-cyan">public key</span> is just a tiny hash of all the sub-keys combined — Hash(Hash(pk₀,pk₁), Hash(pk₂,pk₃)).',
    leaves: ['active','future','future','future'],
    signing: -1, highlight: 'keygen',
  },
  {
    title: 'Week 1 — Officer A Approves',
    text: 'Week 1: Officer A approves a transaction by stamping it with their seal. The approval includes proof that Officer A\'s seal is registered under SecureBank.',
    titleTech: 'Time Period 0 — Sign with Leaf 0',
    textTech: 'Leaf 0 is <span class="c-green">active</span>. We sign the message using leaf 0\'s secret key. The signature includes the actual ML-DSA signature plus the sibling public keys along the tree path, so the verifier can recompute the root hash.',
    leaves: ['active','future','future','future'],
    signing: 0, highlight: 'sign',
  },
  {
    title: 'Officer A\'s Seal is Destroyed',
    text: 'Week 1 ends. Officer A\'s seal is permanently destroyed — shredded in a secure facility. No one can recreate it. Forward secrecy achieved!',
    titleTech: 'Update → Time Period 1',
    textTech: 'We <span class="c-red">securely delete</span> leaf 0\'s secret key and activate leaf 1. The seed for leaf 1 was stored; now we expand it into a full key pair. <strong>Forward secrecy achieved:</strong> even if someone steals the current state, they cannot recover leaf 0\'s key to forge past signatures.',
    leaves: ['deleted','active','future','future'],
    signing: -1, highlight: 'transition',
  },
  {
    title: 'Week 2 — Officer B Approves',
    text: 'Week 2: Officer B takes over and approves transactions with their seal.',
    titleTech: 'Time Period 1 — Sign with Leaf 1',
    textTech: 'Leaf 1 is now <span class="c-green">active</span>. We sign using leaf 1\'s secret key. The signature carries leaf 1\'s ML-DSA signature plus the tree path (pk₀, pk₂, pk₃) so the verifier can walk up to the root.',
    leaves: ['deleted','active','future','future'],
    signing: 1, highlight: 'sign',
  },
  {
    title: 'Officer B\'s Seal is Destroyed',
    text: 'Week 2 ends. Officer B\'s seal is destroyed. Officers A and B\'s seals are both gone forever.',
    titleTech: 'Update → Time Period 2',
    textTech: 'Leaf 1\'s secret key is <span class="c-red">deleted</span>. We cross the midpoint of the tree — now the right subtree activates. Leaf 2\'s key is generated from its stored seed.',
    leaves: ['deleted','deleted','active','future'],
    signing: -1, highlight: 'transition',
  },
  {
    title: 'Week 3 — Officer C Approves',
    text: 'Week 3: Officer C approves transactions. A hacker who compromises the bank now cannot forge Week 1 or Week 2 approvals.',
    titleTech: 'Time Period 2 — Sign with Leaf 2',
    textTech: 'Leaf 2 signs the message. Both leaves 0 and 1 are permanently gone. An attacker who compromises the system now <span class="c-red">cannot forge</span> signatures for T=0 or T=1.',
    leaves: ['deleted','deleted','active','future'],
    signing: 2, highlight: 'sign',
  },
  {
    title: 'Officer C\'s Seal is Destroyed',
    text: 'Week 3 ends. Officer C\'s seal is destroyed. Three seals are now irrecoverable.',
    titleTech: 'Update → Time Period 3',
    textTech: 'Leaf 2 is <span class="c-red">deleted</span>. Leaf 3 (the last one) is activated from its seed. Three previous keys are now irrecoverable.',
    leaves: ['deleted','deleted','deleted','active'],
    signing: -1, highlight: 'transition',
  },
  {
    title: 'Week 4 — Officer D Approves',
    text: 'Week 4: Officer D handles the final week. After this, all seals will be exhausted.',
    titleTech: 'Time Period 3 — Sign with Leaf 3',
    textTech: 'Final time period. Leaf 3 signs the message. After this, all keys will be exhausted. In the full MMM scheme, this tree would be just one level of a larger structure that can keep growing.',
    leaves: ['deleted','deleted','deleted','active'],
    signing: 3, highlight: 'sign',
  },
  {
    title: 'Can a Hacker Forge Past Approvals?',
    text: 'Can a hacker forge past approvals? Each approval is only valid for its own week. The matrix shows: ✓ on the diagonal, ✗ everywhere else. That\'s forward secrecy!',
    titleTech: 'Verification — Does Forward Secrecy Hold?',
    textTech: 'Each signature is only valid at its own time period. Signatures from T=0 <span class="c-green">cannot</span> be verified at T=1,2,3 and vice versa. The matrix below shows: <span class="c-green">✓ True</span> on the diagonal, <span class="c-red">✗ False</span> everywhere else. That\'s forward secrecy!',
    leaves: ['deleted','deleted','deleted','deleted'],
    signing: -1, highlight: 'verify',
  },
];

let sumIdx = 0, sumPlaying = false, sumTimer = null;

function sumDraw() {
  const cv = document.getElementById('sum-canvas');
  const ctx = cv.getContext('2d');
  const W = cv.width, H = cv.height;
  ctx.clearRect(0,0,W,H);

  const step = SUM_STEPS[sumIdx];
  const leafW = 120, leafH = 52, gap = 30;
  const totalW = 4*leafW + 3*gap;
  const startX = (W - totalW) / 2;
  const leafY = H - 80;

  // Draw leaves
  const leafCenters = [];
  for (let i = 0; i < 4; i++) {
    const x = startX + i*(leafW+gap);
    const st = step.leaves[i];
    let fill, border;
    if (st === 'active')  { fill = 'rgba(52,211,153,.15)'; border = C.green; }
    else if (st === 'future')  { fill = 'rgba(139,143,163,.08)'; border = C.muted; }
    else if (st === 'deleted') { fill = 'rgba(220,38,38,.1)'; border = C.deleted; }
    else { fill = 'rgba(251,191,36,.12)'; border = C.orange; }

    roundRect(ctx, x, leafY, leafW, leafH, 8, fill, border);

    // Label
    ctx.fillStyle = border;
    ctx.font = 'bold 13px Inter, sans-serif';
    ctx.textAlign = 'center';
    const leafLabel = technicalMode ? 'Leaf ' + i : 'Officer ' + ['A','B','C','D'][i];
    ctx.fillText(leafLabel, x+leafW/2, leafY+20);
    ctx.font = '11px Inter, sans-serif';
    ctx.fillStyle = C.muted;
    const label = technicalMode
      ? (st === 'active' ? 'sk₊ active' : st === 'future' ? 'seed stored' : 'sk deleted 🗑')
      : (st === 'active' ? '🏦 On Duty' : st === 'future' ? '📨 Waiting' : '🗑️ Seal Destroyed');
    ctx.fillText(label, x+leafW/2, leafY+38);

    leafCenters.push({ x: x+leafW/2, y: leafY });

    // Signing indicator
    if (step.signing === i) {
      ctx.fillStyle = C.orange;
      ctx.font = 'bold 12px Inter, sans-serif';
      ctx.fillText(technicalMode ? '✍ SIGNING' : '✍️ APPROVING', x+leafW/2, leafY+leafH+18);
    }
  }

  // Internal nodes
  const midY1 = leafY - 90;
  const node0x = (leafCenters[0].x + leafCenters[1].x) / 2;
  const node1x = (leafCenters[2].x + leafCenters[3].x) / 2;
  const rootY = midY1 - 90;
  const rootX = (node0x + node1x) / 2;

  // Draw edges
  function edge(x1,y1,x2,y2) {
    ctx.strokeStyle = C.border; ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
  }
  edge(leafCenters[0].x, leafY, node0x, midY1+44);
  edge(leafCenters[1].x, leafY, node0x, midY1+44);
  edge(leafCenters[2].x, leafY, node1x, midY1+44);
  edge(leafCenters[3].x, leafY, node1x, midY1+44);
  edge(node0x, midY1, rootX, rootY+44);
  edge(node1x, midY1, rootX, rootY+44);

  // Internal node boxes
  function internalNode(x, y, label) {
    const nw = 140, nh = 44;
    roundRect(ctx, x-nw/2, y, nw, nh, 8, 'rgba(108,140,255,.1)', C.accent);
    ctx.fillStyle = C.accent;
    ctx.font = 'bold 12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(label, x, y+17);
    ctx.font = '10px Inter, sans-serif';
    ctx.fillStyle = C.muted;
    ctx.fillText('Hash(left, right)', x, y+33);
  }
  internalNode(node0x, midY1, technicalMode ? 'Sum Node L' : 'Department Registry');
  internalNode(node1x, midY1, technicalMode ? 'Sum Node R' : 'Department Registry');
  internalNode(rootX, rootY, technicalMode ? '🔑 Public Key (root)' : '🏦 Bank Identity');

  // Time period bar at bottom
  const barY = H - 18;
  ctx.fillStyle = C.muted;
  ctx.font = '11px Inter, sans-serif';
  ctx.textAlign = 'center';
  for (let i = 0; i < 4; i++) {
    const x = startX + i*(leafW+gap) + leafW/2;
    ctx.fillStyle = step.signing === i ? C.orange : C.muted;
    ctx.fillText('T=' + i, x, barY);
  }
}

function sumUpdateUI() {
  const step = SUM_STEPS[sumIdx];
  const t = technicalMode ? step.titleTech : step.title;
  const tx = technicalMode ? step.textTech : step.text;
  document.getElementById('sum-expl').innerHTML = '<h3>' + t + '</h3><p>' + tx + '</p>';
  document.getElementById('sum-label').textContent =
    'Step ' + (sumIdx+1) + ' / ' + SUM_STEPS.length;
  // Update progress bar
  const sumProgress = document.getElementById('sum-progress');
  if (sumProgress) {
    sumProgress.style.width = ((sumIdx + 1) / SUM_STEPS.length * 100) + '%';
  }
  sumDraw();

  // Show verify grid on last step
  const vs = document.getElementById('sum-verify');
  if (step.highlight === 'verify') {
    vs.style.display = 'block';
    buildVerifyGrid(vs, 4, 'sum');
  } else {
    vs.style.display = 'none';
  }
}

function sumStep() {
  if (sumIdx < SUM_STEPS.length - 1) { sumIdx++; sumUpdateUI(); }
  else { sumPause(); }
}
function sumReset() { sumPause(); sumIdx = 0; sumUpdateUI(); }
function sumPlay() {
  if (sumPlaying) { sumPause(); return; }
  sumPlaying = true;
  document.getElementById('sum-play').textContent = '⏸ Pause';
  sumTimer = setInterval(() => {
    if (sumIdx < SUM_STEPS.length - 1) { sumIdx++; sumUpdateUI(); }
    else { sumPause(); }
  }, 2200);
}
function sumPause() {
  sumPlaying = false;
  document.getElementById('sum-play').textContent = '▶ Play';
  clearInterval(sumTimer);
}

document.getElementById('sum-play').addEventListener('click', sumPlay);
document.getElementById('sum-step').addEventListener('click', sumStep);
document.getElementById('sum-reset').addEventListener('click', sumReset);

sumUpdateUI();

/* ===================================================================
   PRODUCT COMPOSITION ANIMATION
   Product(A, B) where A has 3 epochs, B has 2 sub-periods → 6 total
   =================================================================== */

const T_A = 3, T_B = 2, TOTAL_P = T_A * T_B;

const PROD_STEPS = [
  {
    title: 'SecureBank Organizes into Quarters',
    text: 'SecureBank organizes into 3 quarters, each with 2 weekly officers. A <span class="c-cyan">Branch Manager</span> oversees all quarters and issues <span class="c-orange">authorization letters</span> for each quarter\'s team.',
    titleTech: 'Key Generation',
    textTech: 'Product(A, B) creates <span class="c-cyan">3 epochs</span> × <span class="c-orange">2 sub-periods</span> = 6 total time periods. Scheme A (outer) manages epochs. For each epoch, a fresh instance of scheme B (inner) handles the sub-periods. At keygen, we generate A\'s key pair and the first B instance (B₀). A <span class="c-orange">certifies</span> B₀\'s public key — like a boss signing off on a temporary employee\'s badge.',
    epoch: 0, sub: -1, phase: 'keygen',
    epochs: ['active','future','future'],
    subs: [['ready','future'],null,null],
  },
  {
    title: 'Q1, Week 1 — First Officer Approves',
    text: 'Q1, Week 1: The first officer approves transactions. The approval includes the <span class="c-orange">Branch Manager\'s authorization letter</span> proving this officer is legitimate.',
    titleTech: 'T=0 — Epoch 0, Sub-period 0',
    textTech: 'B₀ signs the message at sub-period 0. The signature contains: (1) B₀\'s actual signature on the message, (2) A\'s certificate on B₀\'s public key, and (3) the time period. The verifier checks both: A certified this B, and B signed this message.',
    epoch: 0, sub: 0, phase: 'sign',
    epochs: ['active','future','future'],
    subs: [['signing','future'],null,null],
  },
  {
    title: 'Q1, Week 1 Ends — Officer Rotates',
    text: 'Q1, Week 1 ends. The first officer\'s seal is destroyed. The second officer takes over — same quarter, same authorization letter.',
    titleTech: 'Update within Epoch 0',
    textTech: 'Still in epoch 0 — we just advance B₀ to sub-period 1. A doesn\'t change. The certificate stays the same (it\'s valid for the whole epoch).',
    epoch: 0, sub: 1, phase: 'update-inner',
    epochs: ['active','future','future'],
    subs: [['deleted','ready'],null,null],
  },
  {
    title: 'Q1, Week 2 — Second Officer Approves',
    text: 'Q1, Week 2: The second officer approves transactions. Week 1\'s seal is already destroyed — <span class="c-green">forward secrecy within the quarter!</span>',
    titleTech: 'T=1 — Epoch 0, Sub-period 1',
    textTech: 'B₀ signs at sub-period 1. Same certificate from A, different B signature. Sub-period 0\'s key is already <span class="c-red">deleted</span> — forward secrecy within the epoch!',
    epoch: 0, sub: 1, phase: 'sign',
    epochs: ['active','future','future'],
    subs: [['deleted','signing'],null,null],
  },
  {
    title: '🔄 Quarter Change! Q1 → Q2',
    text: '🔄 Quarter change! All of Q1\'s officer seals and authorization letter are <span class="c-red">destroyed</span>. The Branch Manager issues a new authorization for Q2\'s team.',
    titleTech: 'Epoch Boundary → Epoch 1',
    textTech: '🔄 <strong>Epoch transition!</strong> B₀ is completely <span class="c-red">erased</span>. A fresh B₁ is generated from the seed chain. A <span class="c-orange">certifies</span> B₁\'s public key and advances its own key. The old seed is consumed — you can\'t go back to B₀.',
    epoch: 1, sub: -1, phase: 'epoch-transition',
    epochs: ['deleted','active','future'],
    subs: [['deleted','deleted'],['ready','future'],null],
  },
  {
    title: 'Q2, Week 1 — New Team, New Authorization',
    text: 'Q2, Week 1: New officer team, new authorization. A hacker who compromises Q2 <span class="c-red">cannot forge anything from Q1</span>.',
    titleTech: 'T=2 — Epoch 1, Sub-period 0',
    textTech: 'B₁ signs at sub-period 0. A\'s new certificate binds B₁ to epoch 1. Even if an attacker gets B₁\'s key, they can\'t forge signatures for epoch 0 — B₀\'s keys and A\'s old epoch-0 key are gone.',
    epoch: 1, sub: 0, phase: 'sign',
    epochs: ['deleted','active','future'],
    subs: [['deleted','deleted'],['signing','future'],null],
  },
  {
    title: 'Q2, Week 1 Ends — Officer Rotates',
    text: 'Q2, Week 1 ends. Officer\'s seal destroyed, next officer takes over.',
    titleTech: 'Update within Epoch 1',
    textTech: 'Advance B₁ to sub-period 1. Same pattern as before — inner key evolves, outer stays.',
    epoch: 1, sub: 1, phase: 'update-inner',
    epochs: ['deleted','active','future'],
    subs: [['deleted','deleted'],['deleted','ready'],null],
  },
  {
    title: 'Q2, Week 2 — Second Officer Approves',
    text: 'Q2, Week 2: Second officer approves. Two quarters of seals are now irrecoverable.',
    titleTech: 'T=3 — Epoch 1, Sub-period 1',
    textTech: 'B₁ signs at sub-period 1. Two epochs worth of keys are now irrecoverable.',
    epoch: 1, sub: 1, phase: 'sign',
    epochs: ['deleted','active','future'],
    subs: [['deleted','deleted'],['deleted','signing'],null],
  },
  {
    title: '🔄 Another Quarter Change! Q2 → Q3',
    text: '🔄 Another quarter change. Q2\'s team <span class="c-red">erased</span>, Q3\'s team authorized.',
    titleTech: 'Epoch Boundary → Epoch 2',
    textTech: '🔄 Another epoch transition. B₁ erased, B₂ generated and certified by A. A advances to its final epoch. The seed chain moves forward — all previous seeds are gone.',
    epoch: 2, sub: -1, phase: 'epoch-transition',
    epochs: ['deleted','deleted','active'],
    subs: [['deleted','deleted'],['deleted','deleted'],['ready','future']],
  },
  {
    title: 'Q3, Week 1 — Four Periods Forward-Secure',
    text: 'Q3, Week 1: Four previous time periods are <span class="c-green">forward-secure</span>.',
    titleTech: 'T=4 — Epoch 2, Sub-period 0',
    textTech: 'B₂ signs at sub-period 0. Four previous time periods are forward-secure.',
    epoch: 2, sub: 0, phase: 'sign',
    epochs: ['deleted','deleted','active'],
    subs: [['deleted','deleted'],['deleted','deleted'],['signing','future']],
  },
  {
    title: 'Q3, Week 1 Ends — Last Inner Rotation',
    text: 'Q3, Week 1 ends. Last inner rotation.',
    titleTech: 'Update within Epoch 2',
    textTech: 'Last inner update. B₂ advances to sub-period 1.',
    epoch: 2, sub: 1, phase: 'update-inner',
    epochs: ['deleted','deleted','active'],
    subs: [['deleted','deleted'],['deleted','deleted'],['deleted','ready']],
  },
  {
    title: 'Q3, Week 2 — Final Time Period',
    text: 'Q3, Week 2: Final time period. All 6 weeks have been covered.',
    titleTech: 'T=5 — Epoch 2, Sub-period 1',
    textTech: 'Final time period. B₂ signs at sub-period 1. After this, all 6 time periods have been used.',
    epoch: 2, sub: 1, phase: 'sign',
    epochs: ['deleted','deleted','active'],
    subs: [['deleted','deleted'],['deleted','deleted'],['deleted','signing']],
  },
  {
    title: 'Two Layers of Protection!',
    text: 'Two layers of protection: within each quarter, old weekly seals are destroyed. Across quarters, old authorization letters are destroyed. A hacker who compromises Q2 <span class="c-red">cannot forge anything from Q1</span>.',
    titleTech: 'Verification — Forward Secrecy Across Two Dimensions',
    textTech: 'The matrix shows every (sign-time, verify-time) combination. <span class="c-green">✓</span> only on the diagonal. Forward secrecy works <em>within</em> epochs (B evolves) and <em>across</em> epochs (A evolves + seed chain is one-way). Two layers of protection!',
    epoch: -1, sub: -1, phase: 'verify',
    epochs: ['deleted','deleted','deleted'],
    subs: [['deleted','deleted'],['deleted','deleted'],['deleted','deleted']],
  },
];

let prodIdx = 0, prodPlaying = false, prodTimer = null;

function prodDraw() {
  const cv = document.getElementById('prod-canvas');
  const ctx = cv.getContext('2d');
  const W = cv.width, H = cv.height;
  ctx.clearRect(0,0,W,H);

  const step = PROD_STEPS[prodIdx];

  // ── Layout constants ──
  const epochW = 240, epochH = 200, epochGap = 30;
  const totalEW = T_A * epochW + (T_A-1) * epochGap;
  const startX = (W - totalEW) / 2;
  const epochY = 130;

  // ── Draw A (top bar) ──
  const aBarY = 30, aBarH = 50;
  roundRect(ctx, startX, aBarY, totalEW, aBarH, 10, 'rgba(108,140,255,.08)', C.accent);
  ctx.fillStyle = C.accent;
  ctx.font = 'bold 14px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(technicalMode ? 'Scheme A — Outer (Epoch Manager)' : 'Branch Manager — Quarterly Oversight', startX + totalEW/2, aBarY + 20);
  ctx.font = '11px Inter, sans-serif';
  ctx.fillStyle = C.muted;
  ctx.fillText(technicalMode ? 'Public key pk_A is the overall public key  •  Certifies each B instance' : 'Oversees all quarters  •  Issues authorization letters for each team', startX + totalEW/2, aBarY + 38);

  // ── Draw epochs ──
  for (let e = 0; e < T_A; e++) {
    const ex = startX + e * (epochW + epochGap);
    const est = step.epochs[e];
    let fill, border;
    if (est === 'active')  { fill = 'rgba(52,211,153,.08)'; border = C.green; }
    else if (est === 'future')  { fill = 'rgba(139,143,163,.05)'; border = C.muted; }
    else { fill = 'rgba(220,38,38,.06)'; border = C.deleted; }

    roundRect(ctx, ex, epochY, epochW, epochH, 10, fill, border);

    // Epoch header
    ctx.fillStyle = border;
    ctx.font = 'bold 13px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(technicalMode ? 'Epoch ' + e : 'Quarter ' + (e + 1), ex + epochW/2, epochY + 22);

    // Certificate arrow from A bar
    if (est === 'active' && step.phase !== 'verify') {
      drawArrow(ctx, ex + epochW/2, aBarY + aBarH, ex + epochW/2, epochY, C.orange);
      ctx.fillStyle = C.orange;
      ctx.font = '10px Inter, sans-serif';
      ctx.fillText(technicalMode ? 'cert' : 'authorization', ex + epochW/2 + 18, (aBarY + aBarH + epochY)/2 + 2);
    } else {
      drawDashedLine(ctx, ex + epochW/2, aBarY + aBarH, ex + epochW/2, epochY, C.border);
    }

    // B instance label
    ctx.fillStyle = est === 'active' ? C.cyan : C.muted;
    ctx.font = '11px Inter, sans-serif';
    ctx.fillText(technicalMode ? 'B' + e + ' instance' : 'Q' + (e + 1) + ' Officer Team', ex + epochW/2, epochY + 42);

    // Sub-period boxes
    if (step.subs[e]) {
      const subW = 90, subH = 70, subGap = 16;
      const subTotalW = T_B * subW + (T_B-1) * subGap;
      const subStartX = ex + (epochW - subTotalW) / 2;
      const subY = epochY + 58;

      for (let s = 0; s < T_B; s++) {
        const sx = subStartX + s * (subW + subGap);
        const sst = step.subs[e][s];
        let sf, sb;
        if (sst === 'signing')     { sf = 'rgba(251,191,36,.15)'; sb = C.orange; }
        else if (sst === 'ready')  { sf = 'rgba(34,211,238,.1)'; sb = C.cyan; }
        else if (sst === 'future') { sf = 'rgba(139,143,163,.05)'; sb = C.muted; }
        else if (sst === 'deleted'){ sf = 'rgba(220,38,38,.08)'; sb = C.deleted; }
        else                       { sf = 'rgba(139,143,163,.05)'; sb = C.muted; }

        roundRect(ctx, sx, subY, subW, subH, 6, sf, sb);

        ctx.fillStyle = sb;
        ctx.font = 'bold 11px Inter, sans-serif';
        ctx.textAlign = 'center';
        const globalT = e * T_B + s;
        ctx.fillText('T=' + globalT, sx + subW/2, subY + 18);

        ctx.font = '10px Inter, sans-serif';
        ctx.fillStyle = C.muted;
        ctx.fillText(technicalMode ? 'sub=' + s : 'Week ' + (s + 1), sx + subW/2, subY + 33);

        // Status icon
        ctx.font = '16px Inter, sans-serif';
        let icon = '';
        if (sst === 'signing') icon = '✍️';
        else if (sst === 'deleted') icon = '🗑';
        else if (sst === 'ready') icon = '🔑';
        else if (sst === 'future') icon = '💤';
        ctx.fillText(icon, sx + subW/2, subY + 56);
      }
    }
  }

  // ── Seed chain at bottom ──
  const chainY = epochY + epochH + 24;
  ctx.fillStyle = C.muted;
  ctx.font = '11px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(
    technicalMode
      ? 'Seed Chain: seed → PRG → (B₀ material, seed\') → PRG → (B₁ material, seed\'\') → ...   [one-way, can\'t go back]'
      : 'Sealed succession plan: each quarter\'s team is prepared from a one-way chain — you can\'t go back to previous quarters',
    W/2, chainY
  );

  // Time period bar
  const barY = chainY + 24;
  for (let t = 0; t < TOTAL_P; t++) {
    const e = Math.floor(t / T_B);
    const s = t % T_B;
    const ex = startX + e * (epochW + epochGap);
    const subW = 90, subGap = 16;
    const subTotalW = T_B * subW + (T_B-1) * subGap;
    const subStartX = ex + (epochW - subTotalW) / 2;
    const sx = subStartX + s * (subW + subGap) + subW/2;

    const isActive = step.subs[e] && step.subs[e][s] === 'signing';
    ctx.fillStyle = isActive ? C.orange : C.muted;
    ctx.font = (isActive ? 'bold ' : '') + '11px Inter, sans-serif';
    ctx.fillText('T=' + t, sx, barY);
  }
}

function prodUpdateUI() {
  const step = PROD_STEPS[prodIdx];
  const t = technicalMode ? step.titleTech : step.title;
  const tx = technicalMode ? step.textTech : step.text;
  document.getElementById('prod-expl').innerHTML =
    '<h3>' + t + '</h3><p>' + tx + '</p>';
  document.getElementById('prod-label').textContent =
    'Step ' + (prodIdx+1) + ' / ' + PROD_STEPS.length;
  // Update progress bar
  const prodProgress = document.getElementById('prod-progress');
  if (prodProgress) {
    prodProgress.style.width = ((prodIdx + 1) / PROD_STEPS.length * 100) + '%';
  }
  prodDraw();

  const vs = document.getElementById('prod-verify');
  if (step.phase === 'verify') {
    vs.style.display = 'block';
    buildVerifyGrid(vs, TOTAL_P, 'prod');
  } else {
    vs.style.display = 'none';
  }
}

function prodStep() {
  if (prodIdx < PROD_STEPS.length - 1) { prodIdx++; prodUpdateUI(); }
  else { prodPause(); }
}
function prodReset() { prodPause(); prodIdx = 0; prodUpdateUI(); }
function prodPlay() {
  if (prodPlaying) { prodPause(); return; }
  prodPlaying = true;
  document.getElementById('prod-play').textContent = '⏸ Pause';
  prodTimer = setInterval(() => {
    if (prodIdx < PROD_STEPS.length - 1) { prodIdx++; prodUpdateUI(); }
    else { prodPause(); }
  }, 2800);
}
function prodPause() {
  prodPlaying = false;
  document.getElementById('prod-play').textContent = '▶ Play';
  clearInterval(prodTimer);
}

document.getElementById('prod-play').addEventListener('click', prodPlay);
document.getElementById('prod-step').addEventListener('click', prodStep);
document.getElementById('prod-reset').addEventListener('click', prodReset);

prodUpdateUI();

/* ===================================================================
   VERIFICATION GRID — shared by both panels
   =================================================================== */

function buildVerifyGrid(container, total, prefix) {
  const headerText = technicalMode 
    ? 'Verification Matrix — sign at row, verify at column'
    : 'Can a hacker forge past approvals? Each row is when a transaction was signed, each column is when someone tries to verify it.';
  container.innerHTML = '<h3 style="font-size:.92rem;color:#6c8cff;margin-bottom:10px">' + headerText + '</h3>';
  const grid = document.createElement('div');
  grid.className = 'vgrid';
  grid.style.gridTemplateColumns = 'auto ' + 'repeat(' + total + ', 1fr)';

  // Header row
  const corner = document.createElement('div');
  corner.className = 'vcell hdr';
  corner.textContent = 'sign \\ verify';
  grid.appendChild(corner);
  for (let v = 0; v < total; v++) {
    const h = document.createElement('div');
    h.className = 'vcell hdr';
    h.textContent = 'T=' + v;
    grid.appendChild(h);
  }

  // Data rows
  for (let s = 0; s < total; s++) {
    const rh = document.createElement('div');
    rh.className = 'vcell hdr';
    rh.textContent = 'T=' + s;
    grid.appendChild(rh);
    for (let v = 0; v < total; v++) {
      const cell = document.createElement('div');
      if (s === v) {
        cell.className = 'vcell pass';
        cell.textContent = '✓ True';
      } else {
        cell.className = 'vcell fail';
        cell.textContent = '✗ False';
      }
      grid.appendChild(cell);
    }
  }

  container.appendChild(grid);

  // Animate cells appearing
  const cells = grid.querySelectorAll('.vcell:not(.hdr)');
  cells.forEach((c, i) => {
    c.style.opacity = '0';
    c.style.transform = 'scale(0.8)';
    setTimeout(() => {
      c.style.transition = 'all 0.3s ease';
      c.style.opacity = '1';
      c.style.transform = 'scale(1)';
    }, 40 * i);
  });
}

/* ===================================================================
   FULL MMM SCHEME ANIMATION
   MMM(S, l=4): 4 epochs, 15 total time periods
   Epoch 0: t=0 (1 sub)   Epoch 1: t=1-2 (2 subs)
   Epoch 2: t=3-6 (4 subs) Epoch 3: t=7-14 (8 subs)
   =================================================================== */

const MMM_L = 4;
const MMM_TOTAL = (1 << MMM_L) - 1; // 15

function mmmEpoch(t) { return Math.floor(Math.log2(t + 1)); }
function mmmSub(t)   { const e = mmmEpoch(t); return t - ((1 << e) - 1); }
function mmmEpochSize(e) { return 1 << e; }
function mmmEpochStart(e) { return (1 << e) - 1; }

// Build step data for all 15 time periods + keygen + verify
function buildMMMSteps() {
  const steps = [];

  // Step 0: keygen
  steps.push({
    title: 'SecureBank\'s Board of Directors',
    text: 'SecureBank\'s <span class="c-accent2">Board of Directors</span> oversees all quarters. Q1 has 1 week, Q2 has 2 weeks, Q3 has 4 weeks, Q4 has 8 weeks — the bank scales up as business grows.',
    titleTech: 'Key Generation',
    textTech: 'The MMM scheme builds a <span class="c-accent2">top-level SumTree L</span> with depth=2 (4 leaves, one per epoch). ' +
      'The public key pk_L is just a tiny hash — the root of L\'s tree. ' +
      'Then it creates <span class="c-cyan">B₀</span> (a single ML-DSA instance for epoch 0) and L <span class="c-orange">certifies</span> B₀\'s public key. ' +
      'The key insight: each epoch\'s bottom tree <em>grows</em> — epoch e gets depth e, so 2ᵉ sub-periods.',
    activeT: -1, phase: 'keygen',
  });

  // Steps for each time period: sign
  for (let t = 0; t < MMM_TOTAL; t++) {
    const e = mmmEpoch(t);
    const s = mmmSub(t);
    const eSize = mmmEpochSize(e);
    const isEpochStart = (s === 0 && t > 0);

    if (isEpochStart) {
      // Epoch transition step
      steps.push({
        title: `🔄 Quarter Change! Q${e} → Q${e + 1}`,
        text: `🔄 Quarter change! The Board authorizes a new, larger team for Q${e + 1}. Q${e + 1} has ${eSize} weeks — the bank scales up as business grows.`,
        titleTech: `Epoch Boundary → Epoch ${e}`,
        textTech: `🔄 <strong>Epoch transition!</strong> B${e-1} is completely <span class="c-red">erased</span>. ` +
          `A new <span class="c-cyan">B${e}</span> is built as a SumTree of depth ${e} (${eSize} sub-periods). ` +
          `L <span class="c-orange">certifies</span> B${e}'s public key at epoch ${e} and advances its own key. ` +
          `The seed chain moves forward — all previous seeds are gone.`,
        activeT: t, phase: 'epoch-transition',
      });
    }

    steps.push({
      title: `Q${e + 1}, Week ${s + 1} — Officer Approves`,
      text: `Q${e + 1}, Week ${s + 1}: Officer approves transactions. ` +
        (e > 0 ? `All previous quarters' seals are <span class="c-red">permanently destroyed</span>. ` : '') +
        (s > 0 ? `Weeks 1–${s} within this quarter are also destroyed. ` : '') +
        `Forward secrecy at every level!`,
      titleTech: `T=${t} — Epoch ${e}, Sub-period ${s}`,
      textTech: `B${e} signs the message at sub-period ${s}. ` +
        (e > 0 ? `All keys from epochs 0–${e-1} are <span class="c-red">permanently deleted</span>. ` : '') +
        (s > 0 ? `Sub-periods 0–${s-1} within this epoch are also deleted. ` : '') +
        `The signature contains: B${e}'s signature + L's certificate binding B${e} to epoch ${e}.`,
      activeT: t, phase: 'sign',
    });
  }

  // Final verify step
  steps.push({
    title: 'The Bank Never Stops Growing!',
    text: 'The bank never needed to decide upfront how many weeks it would operate. Each quarter is bigger than the last. <span class="c-green">Forward secrecy at every level!</span>',
    titleTech: 'Verification — Unbounded Forward Secrecy',
    textTech: 'All 15 signatures are valid at their own time period. All 210 cross-time forgery attempts fail. ' +
      'Forward secrecy works at <em>two levels</em>: within each epoch (B\'s SumTree evolves) and across epochs ' +
      '(L evolves + seed chain is one-way). The scheme never needed to fix the total number of periods upfront — ' +
      'epoch 0 has 1 period, epoch 1 has 2, epoch 2 has 4, epoch 3 has 8. It just keeps growing.',
    activeT: -1, phase: 'verify',
  });

  return steps;
}

const MMM_STEPS = buildMMMSteps();
let mmmIdx = 0, mmmPlaying = false, mmmTimer = null;

function mmmDraw() {
  const cv = document.getElementById('mmm-canvas');
  const ctx = cv.getContext('2d');
  const W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);

  const step = MMM_STEPS[mmmIdx];
  const activeT = step.activeT;
  const activeEpoch = activeT >= 0 ? mmmEpoch(activeT) : -1;
  const activeSub = activeT >= 0 ? mmmSub(activeT) : -1;

  // Determine which epochs are deleted/active/future
  function epochStatus(e) {
    if (step.phase === 'verify') return 'deleted';
    if (step.phase === 'keygen') return e === 0 ? 'active' : 'future';
    if (e < activeEpoch) return 'deleted';
    if (e === activeEpoch) return 'active';
    return 'future';
  }

  function subStatus(e, s) {
    const est = epochStatus(e);
    if (est === 'deleted') return 'deleted';
    if (est === 'future') return 'future';
    // active epoch
    if (step.phase === 'epoch-transition' && s === 0) return 'ready';
    if (step.phase === 'epoch-transition') return 'future';
    if (s < activeSub) return 'deleted';
    if (s === activeSub) return step.phase === 'sign' ? 'signing' : 'ready';
    return 'future';
  }

  // ── Top-level tree L ──
  const topY = 16, topH = 56;
  const topW = W - 60;
  const topX = 30;
  roundRect(ctx, topX, topY, topW, topH, 10, 'rgba(108,140,255,.08)', C.accent);
  ctx.fillStyle = C.accent;
  ctx.font = 'bold 13px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(technicalMode ? 'Top-Level Tree L — SumTree(S, depth=2) — 4 leaves, one per epoch' : 'Board of Directors — Oversees All Quarters', topX + topW/2, topY + 20);
  ctx.font = '11px Inter, sans-serif';
  ctx.fillStyle = C.muted;
  ctx.fillText(technicalMode ? 'pk_L = Hash(Hash(pk₀,pk₁), Hash(pk₂,pk₃))  ←  THE PUBLIC KEY (just a hash!)' : 'The Board authorizes each quarter\'s team and issues authorization letters', topX + topW/2, topY + 38);

  // Draw L's 4 leaf indicators
  const leafBarY = topY + topH - 4;
  const leafW = topW / 4 - 6;
  for (let e = 0; e < MMM_L; e++) {
    const lx = topX + 3 + e * (leafW + 6);
    const est = epochStatus(e);
    let col;
    if (est === 'active') col = C.green;
    else if (est === 'deleted') col = C.deleted;
    else col = C.muted;
    ctx.fillStyle = col;
    ctx.globalAlpha = est === 'future' ? 0.3 : 0.7;
    roundRect(ctx, lx, leafBarY, leafW, 5, 2, col, null);
    ctx.globalAlpha = 1;
  }

  // ── Epoch boxes ──
  const epochAreaY = topY + topH + 30;
  // Variable-width epochs: epoch e gets proportional width to 2^e
  const totalSubs = MMM_TOTAL; // 15
  const epochGap = 8;
  const availW = W - 60 - (MMM_L - 1) * epochGap;
  const subUnitW = availW / totalSubs;

  let curX = 30;
  for (let e = 0; e < MMM_L; e++) {
    const eSize = mmmEpochSize(e);
    const eW = eSize * subUnitW;
    const est = epochStatus(e);

    let fill, border;
    if (est === 'active')  { fill = 'rgba(52,211,153,.06)'; border = C.green; }
    else if (est === 'future')  { fill = 'rgba(139,143,163,.04)'; border = C.muted; }
    else { fill = 'rgba(220,38,38,.04)'; border = C.deleted; }

    const eH = 160;
    roundRect(ctx, curX, epochAreaY, eW, eH, 8, fill, border);

    // Epoch header
    ctx.fillStyle = border;
    ctx.font = 'bold 11px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(technicalMode ? `Epoch ${e}` : `Quarter ${e + 1}`, curX + eW/2, epochAreaY + 16);

    // B label
    ctx.font = '10px Inter, sans-serif';
    ctx.fillStyle = est === 'active' ? C.cyan : C.muted;
    ctx.fillText(technicalMode ? `B${e} depth=${e}` : `Q${e + 1} Team`, curX + eW/2, epochAreaY + 30);
    ctx.fillText(`${eSize} sub${eSize > 1 ? 's' : ''}`, curX + eW/2, epochAreaY + 42);

    // Certificate arrow
    if (est === 'active' && step.phase !== 'verify') {
      drawArrow(ctx, curX + eW/2, topY + topH + 2, curX + eW/2, epochAreaY, C.orange);
      ctx.fillStyle = C.orange;
      ctx.font = '9px Inter, sans-serif';
      ctx.fillText(technicalMode ? 'cert' : 'authorization', curX + eW/2 + 14, epochAreaY - 10);
    } else {
      drawDashedLine(ctx, curX + eW/2, topY + topH + 2, curX + eW/2, epochAreaY, C.border);
    }

    // Sub-period boxes inside epoch
    const subAreaY = epochAreaY + 50;
    const subH = 44;
    const subGap = 2;
    const subAvailW = eW - 8;
    const singleSubW = Math.max(14, (subAvailW - (eSize - 1) * subGap) / eSize);

    // Only draw individual sub boxes if they fit (epoch 3 has 8 subs)
    const drawIndividual = singleSubW >= 14;

    if (drawIndividual) {
      const subTotalW = eSize * singleSubW + (eSize - 1) * subGap;
      let sx = curX + (eW - subTotalW) / 2;

      for (let s = 0; s < eSize; s++) {
        const sst = subStatus(e, s);
        let sf, sb;
        if (sst === 'signing')     { sf = 'rgba(251,191,36,.15)'; sb = C.orange; }
        else if (sst === 'ready')  { sf = 'rgba(34,211,238,.1)'; sb = C.cyan; }
        else if (sst === 'future') { sf = 'rgba(139,143,163,.04)'; sb = C.muted; }
        else                       { sf = 'rgba(220,38,38,.06)'; sb = C.deleted; }

        roundRect(ctx, sx, subAreaY, singleSubW, subH, 4, sf, sb);

        const globalT = mmmEpochStart(e) + s;
        ctx.fillStyle = sb;
        ctx.font = singleSubW > 30 ? 'bold 10px Inter, sans-serif' : 'bold 8px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(`T=${globalT}`, sx + singleSubW/2, subAreaY + 14);

        if (singleSubW > 24) {
          ctx.font = '8px Inter, sans-serif';
          ctx.fillStyle = C.muted;
          ctx.fillText(technicalMode ? `s=${s}` : `Wk ${s + 1}`, sx + singleSubW/2, subAreaY + 26);
        }

        // Icon
        if (singleSubW > 20) {
          ctx.font = '12px Inter, sans-serif';
          let icon = '';
          if (sst === 'signing') icon = '✍️';
          else if (sst === 'deleted') icon = '🗑';
          else if (sst === 'ready') icon = '🔑';
          else if (sst === 'future') icon = '💤';
          ctx.fillText(icon, sx + singleSubW/2, subAreaY + 40);
        }

        sx += singleSubW + subGap;
      }
    } else {
      // Compact view for large epochs
      ctx.fillStyle = C.muted;
      ctx.font = '10px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(`${eSize} sub-periods`, curX + eW/2, subAreaY + 20);
    }

    // Epoch time range at bottom
    const rangeY = epochAreaY + eH - 8;
    ctx.fillStyle = C.muted;
    ctx.font = '9px Inter, sans-serif';
    ctx.textAlign = 'center';
    const tStart = mmmEpochStart(e);
    const tEnd = tStart + eSize - 1;
    ctx.fillText(tStart === tEnd ? `t=${tStart}` : `t=${tStart}–${tEnd}`, curX + eW/2, rangeY);

    curX += eW + epochGap;
  }

  // ── Growth formula ──
  const formulaY = epochAreaY + 175;
  ctx.fillStyle = C.muted;
  ctx.font = '11px Inter, sans-serif';
  ctx.textAlign = 'center';
  if (technicalMode) {
    ctx.fillText('Total periods = 2⁰ + 2¹ + 2² + 2³ = 1 + 2 + 4 + 8 = 15 = 2⁴ − 1', W/2, formulaY);
    ctx.fillText('epoch(t) = ⌊log₂(t+1)⌋     sub(t) = t − (2^epoch − 1)', W/2, formulaY + 18);
  } else {
    ctx.fillText('Total weeks = 1 + 2 + 4 + 8 = 15 — the bank keeps growing!', W/2, formulaY);
    ctx.fillText('Each quarter is bigger than the last — the bank never needs to decide upfront how long it will operate', W/2, formulaY + 18);
  }

  // ── Seed chain ──
  const chainY = formulaY + 38;
  ctx.fillStyle = C.muted;
  ctx.font = '10px Inter, sans-serif';
  ctx.fillText(
    technicalMode
      ? 'Seed chain: seed → PRG → (B₀, seed\') → PRG → (B₁, seed\'\') → PRG → (B₂, seed\'\'\') → ...  [one-way]'
      : 'Sealed succession plan: each quarter\'s team is prepared from a one-way chain — you can\'t go back to previous quarters',
    W/2, chainY
  );
}

function mmmUpdateUI() {
  const step = MMM_STEPS[mmmIdx];
  const t = technicalMode ? step.titleTech : step.title;
  const tx = technicalMode ? step.textTech : step.text;
  document.getElementById('mmm-expl').innerHTML =
    '<h3>' + t + '</h3><p>' + tx + '</p>';
  document.getElementById('mmm-label').textContent =
    'Step ' + (mmmIdx + 1) + ' / ' + MMM_STEPS.length;
  // Update progress bar
  const mmmProgress = document.getElementById('mmm-progress');
  if (mmmProgress) {
    mmmProgress.style.width = ((mmmIdx + 1) / MMM_STEPS.length * 100) + '%';
  }
  mmmDraw();

  const vs = document.getElementById('mmm-verify');
  if (step.phase === 'verify') {
    vs.style.display = 'block';
    buildVerifyGrid(vs, MMM_TOTAL, 'mmm');
  } else {
    vs.style.display = 'none';
  }
}

function mmmStep() {
  if (mmmIdx < MMM_STEPS.length - 1) { mmmIdx++; mmmUpdateUI(); }
  else { mmmPause(); }
}
function mmmReset() { mmmPause(); mmmIdx = 0; mmmUpdateUI(); }
function mmmPlay() {
  if (mmmPlaying) { mmmPause(); return; }
  mmmPlaying = true;
  document.getElementById('mmm-play').textContent = '⏸ Pause';
  mmmTimer = setInterval(() => {
    if (mmmIdx < MMM_STEPS.length - 1) { mmmIdx++; mmmUpdateUI(); }
    else { mmmPause(); }
  }, 2000);
}
function mmmPause() {
  mmmPlaying = false;
  document.getElementById('mmm-play').textContent = '▶ Play';
  clearInterval(mmmTimer);
}

document.getElementById('mmm-play').addEventListener('click', mmmPlay);
document.getElementById('mmm-step').addEventListener('click', mmmStep);
document.getElementById('mmm-reset').addEventListener('click', mmmReset);

mmmUpdateUI();
