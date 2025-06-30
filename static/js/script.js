let quill = null;
let currentView = null;
let currentEmployeePage = 1;
const employeesPerPage = 15;
const flatpickrInstances = {};
let employeeFilters = JSON.parse(localStorage.getItem('employeeFilters')) || {
  name: '',
  email: '',
  department: '',
  role: '',
  search: '',
  sort: '',
  order: ''
};
let isRedirecting = false;
let lastSessionCheck = 0;
let employeeChart = null;        // ✅ ここで一度だけ定義
let timebandChart = null;
let departmentChart = null;
let currentUserId = null;
let templates = [];
let campaigns = [];
let employeeClicksChart = null;

// CSRF トークンを AJAX に設定
$.ajaxSetup({
  beforeSend: function(xhr, settings) {
    if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
      const csrfToken = $('meta[name="csrf_token"]').attr('content');
      if (csrfToken) {
        xhr.setRequestHeader('X-CSRF-Token', csrfToken);
        console.log('🔒 Added CSRF token to request:', settings.url);
      } else {
        console.warn('⚠️ CSRF token not found in meta tag');
      }
    }
  }
});

// ビュー切り替え用共通関数（すでにあるなら再利用）
function showView(viewId) {
    $('.content-section').hide();            // すべて非表示
    $('#' + viewId).show();                  // 指定ビューのみ表示
}

// ナビゲーションリンクにイベントバインド
$(document).on('click', '.nav-link[data-view]', function (e) {
    e.preventDefault();
    const viewId = $(this).data('view');    // 例: "employee-portal"
    console.log('🔄 Nav click:', viewId);
    showView(viewId);
});


function loadSignaturePreview(templateId) {
  fetch("/api/employee/signature", {
    method: "POST",
    body: JSON.stringify({ template_id: templateId }),
    headers: {
      "Content-Type": "application/json"
    }
  })
  .then(res => res.json())
  .then(data => {
    if (data.success && data.signature_html) {
      const previewElement = document.getElementById("signature-preview");
      if (previewElement) {
        previewElement.innerHTML = data.signature_html;
      } else {
        console.warn("❌ #signature-preview element not found");
      }
    } else {
      console.warn("⚠️ Failed to load signature preview:", data.message);
    }
  })
  .catch(err => {
    console.error("❌ Error fetching signature preview:", err);
  });
}

document.addEventListener("DOMContentLoaded", function () {
  const dateRangeInput = document.querySelector("#date-range");
  if (dateRangeInput) {
    flatpickr(dateRangeInput, {
      mode: "range",
      enableTime: true,
      time_24hr: true,
      dateFormat: "Y-m-d H:i:S",
      locale: "ja",
      onReady: function (selectedDates, dateStr, instance) {
        flatpickrInstances.dateRange = instance;
        console.log("✅ flatpickr is fully ready");
      }
    });
  }
});












// トースト通知を表示
function showToast(message, type = 'success') {
  console.log(`🟢 [Toast suppressed] ${message}`);
}


// セッション状態を確認
function checkSession(callback) {
  const now = Date.now();
  if (now - lastSessionCheck < 30000) {
    console.log('🔍 Skipping session check (recently checked)');
    callback(true, null);
    return;
  }
  console.log('🔍 Checking session');
  $.ajax({
    url: '/api/session',
    method: 'GET',
    timeout: 5000,
    success: function(data) {
      lastSessionCheck = now;
      console.log('🔵 Session response:', data);
      if (data.success && data.authenticated) {
        console.log('✅ Session valid:', data.user);
        callback(true, data);
      } else {
        console.warn('⚠️ Session invalid:', data.message || 'No authenticated user');
        callback(false, data);
      }
    },
    error: function(xhr) {
      lastSessionCheck = now;
      console.error('❌ Session check failed:', xhr.status, xhr.statusText, xhr.responseJSON);
      callback(false, null);
    }
  });
}

// 認証ページにリダイレクト
function redirectToAuth(message) {
  if (isRedirecting) {
    console.log('🔄 Already redirecting, skipping');
    return;
  }
  isRedirecting = true;
  console.warn('➡️ Redirecting to /auth:', message);
  showToast(message, 'danger');
  setTimeout(() => {
    window.location.href = '/auth';
    isRedirecting = false;
  }, 3000);
}

// 日付をJST形式にフォーマット
function formatToJST(rawDate) {
  if (!rawDate) {
    console.warn('⚠️ Invalid date input: empty or null');
    return '不明';
  }
  let cleanISO;
  if (rawDate.match(/^\d{4}\/\d{2}\/\d{2}\d{2}:\d{2}:\d{2}$/)) {
    cleanISO = rawDate.replace(/\//g, '-').replace(' ', 'T') + 'Z';
  } else {
    cleanISO = rawDate.replace(/\.\d+/, '') + 'Z';
  }
  const date = new Date(cleanISO);
  if (isNaN(date)) {
    console.warn('⚠️ Invalid date format:', rawDate);
    return '不明';
  }
  return date.toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).replace(/(\d+)\/(\d+)\/(\d+), (\d+:\d+:\d+)/, '$1/$2/$3 $4');
}

// HTMLエスケープ
function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&apos;'
  };
  return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// プレースホルダー挿入ハンドラ
function handlePlaceholderInsert(e) {
  e.preventDefault();
  const $button = $(this);
  const placeholder = $button.data('placeholder');
  console.log('🔵 Inserting placeholder:', placeholder);
  if (!placeholder) {
    console.error('❌ No placeholder value found');
    showToast('プレースホルダーが設定されていません', 'danger');
    return;
  }
  if (!quill) {
    console.error('❌ Quill instance is not initialized');
    showToast('エディタが初期化されていません', 'danger');
    return;
  }
  try {
    const range = quill.getSelection(true) || { index: quill.getLength() };
    quill.insertText(range.index, placeholder);
    quill.setSelection(range.index + placeholder.length);
    $('#html-content').val(quill.root.innerHTML);
    console.log('✅ Inserted placeholder:', placeholder);
    showToast(`プレースホルダー ${placeholder} を挿入しました`, 'success');
    updateIframePreview();
  } catch (error) {
    console.error('❌ Error inserting placeholder:', error);
    showToast('プレースホルダー挿入に失敗しました', 'danger');
  }
}

// ✅ クリック時にトラッキングリンクを生成してQuillに挿入
function handleGenerateTrack(e) {
  e.preventDefault();

  const url = prompt('トラッキングするURLを入力してください:');
  if (!url || !/^https?:\/\//.test(url)) {
    console.warn('🟡 無効なURL:', url);
    showToast('有効なURLを入力してください', 'warning');
    return;
  }

  const $form = $('#template-form');
  const templateId = $form.data('template-id') || $form.data('id') || 'unsaved';
  console.log('🟢 templateId（仮含む）:', templateId);

  // 保存済みならサーバーに送信、それ以外は仮プレースホルダーで挿入
  if (templateId !== 'unsaved') {
    // 通常のトラッキング登録処理
    $.ajax({
      url: '/api/tracking/link',
      method: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ url: url, template_id: templateId }),
      success: function(res) {
        console.log('🟢 サーバー応答:', res);

        if (res.success && res.track_id) {
          const placeholder = `{{tracking_link_${res.track_id}}}`;
          insertTrackingLink(url, placeholder);
        } else {
          showToast(res.message || '生成に失敗しました', 'danger');
        }
      },
      error: function(xhr, status, err) {
        console.error('❌ 通信エラー:', status, err);
        showToast('通信エラーで生成に失敗しました', 'danger');
      }
    });
  } else {
    // 未保存テンプレートには仮のプレースホルダー
    const placeholder = `{{tracking_link_temp_${Date.now()}}}`;
    insertTrackingLink(url, placeholder);
    showToast('⚠️ 未保存テンプレートのため仮リンクを挿入しました', 'warning');
  }
}

// ✅ 共通のQuill挿入処理
function insertTrackingLink(displayUrl, hrefValue) {
  if (!quill) {
    console.error('❌ Quillが初期化されていません');
    showToast('エディタが初期化されていません', 'danger');
    return;
  }

  const range = quill.getSelection(true) || { index: quill.getLength() };
  console.log('🟢 挿入位置:', range);
  console.log('🟢 href:', hrefValue);

  quill.insertText(range.index, displayUrl, 'link', hrefValue);
  quill.setSelection(range.index + displayUrl.length);
  $('#html-content').val(quill.root.innerHTML);
  updateIframePreview();

  $('#tracking-url-container').html(`
    <div class="alert alert-info mt-2">
      以下を挿入しました:<br>
      <code>${displayUrl}</code> → <code>${hrefValue}</code>
    </div>
  `);
}



$(document).on('click', '.delete-campaign', function () {
  const id = $(this).data('id');
  if (!confirm('このキャンペーンを削除してもよろしいですか？')) return;

  $.ajax({
    url: `/api/campaigns/${id}`,
    type: 'DELETE',
    success: function (res) {
      if (res.success) {
        showToast(res.message || '削除しました', 'success');
        loadCampaigns();  // リストを再読み込み
      } else {
        showToast('削除に失敗しました', 'danger');
      }
    },
    error: function (xhr) {
      console.error('❌ DELETE error:', xhr.status, xhr.statusText);
      showToast('削除に失敗しました', 'danger');
    }
  });
});


function waitForFlatpickrReady(campaign, retry = 0) {
  if (flatpickrInstances.dateRange && typeof flatpickrInstances.dateRange.setDate === 'function') {
    flatpickrInstances.dateRange.setDate([campaign.start_date, campaign.end_date]);
    console.log("✅ flatpickr.setDate 完了");
  } else if (retry < 10) {
    console.log(`⏳ flatpickr待機中... retry=${retry}`);
    setTimeout(() => waitForFlatpickrReady(campaign, retry + 1), 200);
  } else {
    console.error("❌ flatpickr 初期化失敗（タイムアウト）");
  }
}



$(document).on('click', '.edit-campaign', function () {
  const id = $(this).data('id');
  const campaign = campaigns.find(c => c.id === id);
  if (!campaign) return;

  $('#template-ids').val(campaign.template_ids);
  $('#department').val(campaign.department || '');
  $('#campaign-form').data('editing-id', campaign.id);
  $('#campaign-form-container').show();

  waitForFlatpickrReady(campaign); // 🔥 ここで遅延確認付きでセット

  showToast('編集モードに入りました。修正後、保存してください。', 'info');
});













// フォーム送信処理（新規 or 更新）
$('#campaign-form').off('submit').on('submit', function (e) {
  e.preventDefault();

  const editingId = $(this).data('editing-id');
  const templateIds = $('#template-ids').val();
  const department = $('#department').val();
  const dateRange = $('#date-range').val().split(' to ');
  const data = {
    template_ids: templateIds,
    department: department || null,
    start_date: dateRange[0],
    end_date: dateRange[1] || dateRange[0]
  };

  const method = editingId ? 'PUT' : 'POST';
  const url = editingId ? `/api/campaigns/${editingId}` : '/api/campaigns';

  $.ajax({
    url,
    method,
    contentType: 'application/json',
    data: JSON.stringify(data),
    success: function (response) {
      showToast(response.message || '保存しました', 'success');
      $('#campaign-form')[0].reset();
      $('#campaign-form').removeData('editing-id');
      loadCampaigns();
    },
    error: function (xhr) {
      console.error('❌ 保存エラー:', xhr.status, xhr.statusText);
      showToast(xhr.responseJSON?.message || '保存に失敗しました', 'danger');
    }
  });
});













// トラッキングURLをUIに表示
function displayTrackingUrl(trackUrl, trackId) {
  console.log('🔵 Displaying tracking URL:', trackUrl, 'Track ID:', trackId);
  const $container = $('#tracking-url-container');
  const html = `
    <div class="alert alert-info">
      <h5>生成されたトラッキングリンク</h5>
      <p><a href="${trackUrl}" target="_blank" class="tracking-link">${trackUrl}</a></p>
      <p>トラックID: ${trackId}</p>
      <button class="btn btn-primary btn-sm test-tracking-btn" data-track-id="${trackId}" data-url="${trackUrl}">テストクリック</button>
      <button class="btn btn-secondary btn-sm copy-tracking-btn" data-clipboard-text="${trackUrl}">リンクをコピー</button>
    </div>
  `;
  $container.html(html);
  $('.test-tracking-btn').off('click').on('click', function() {
    const trackId = $(this).data('track-id');
    const url = $(this).data('url');
    console.log('🧪 Testing tracking URL:', url, 'Track ID:', trackId);
    $.ajax({
      url: `/api/click/${trackId}`,
      method: 'GET',
      success: function() {
        console.log('✅ Tracking URL test successful');
        $.get(`/api/analytics?track_id=${trackId}`, function(data) {
          const track = data.find(t => t.track_id === trackId);
          showToast(`トラッキングリンクのテスト成功: クリック数=${track ? track.clicks : 0}`, 'success');
        }).fail(function(xhr) {
          console.error('❌ Failed to fetch click count:', xhr.status, xhr.statusText);
          showToast('クリック数確認に失敗しました', 'danger');
        });
      },
      error: function(xhr) {
        console.error('❌ Tracking URL test failed:', xhr.status, xhr.statusText);
        showToast('トラッキングリンクのテストに失敗しました', 'danger');
      }
    });
  });
  $('.copy-tracking-btn').off('click').on('click', function() {
    const text = $(this).data('clipboard-text');
    console.log('📋 Copying tracking URL:', text);
    navigator.clipboard.writeText(text).then(() => {
      console.log('✅ Copied to clipboard');
      showToast('トラッキングリンクをクリップボードにコピーしました', 'success');
    }).catch(err => {
      console.error('❌ Clipboard copy error:', err);
      showToast('コピーに失敗しました', 'danger');
    });
  });
  showTrackingUrlModal(trackUrl, trackId);
}

// script.js
$(document).on('click', '#logout-link', function(e) {
  e.preventDefault();
  const csrfToken = $('meta[name="csrf_token"]').attr('content');
  console.log('🚪 Logging out...');

  $.ajax({
    type: 'POST',
    url: '/api/logout',
    headers: { 'X-CSRFToken': csrfToken },
    success: function(res) {
      if (res.success) {
        window.location.href = '/auth';
      } else {
        showToast('ログアウトに失敗しました', 'danger');
      }
    },
    error: function(xhr) {
      console.error('❌ Logout failed:', xhr.status, xhr.statusText);
      showToast('ログアウトに失敗しました', 'danger');
    }
  });
});



// トラッキングURLをモーダルで表示
function showTrackingUrlModal(trackUrl, trackId) {
  console.log('🔵 Showing tracking URL modal:', trackUrl, 'Track ID:', trackId);
  const $modal = $('#trackingUrlModal');
  $modal.find('.modal-body').html(`
    <p><strong>トラッキングリンク:</strong> <a href="${trackUrl}" target="_blank" class="tracking-link">${trackUrl}</a></p>
    <p><strong>トラックID:</strong> ${trackId}</p>
    <button class="btn btn-primary btn-sm test-tracking-btn" data-track-id="${trackId}" data-url="${trackUrl}">テストクリック</button>
    <button class="btn btn-secondary btn-sm copy-tracking-btn" data-clipboard-text="${trackUrl}">リンクをコピー</button>
  `);
  $modal.find('.test-tracking-btn').off('click').on('click', function() {
    const trackId = $(this).data('track-id');
    const url = $(this).data('url');
    console.log('🧪 Testing tracking URL from modal:', url, 'Track ID:', trackId);
    $.ajax({
      url: `/api/click/${trackId}`,
      method: 'GET',
      success: function() {
        console.log('✅ Tracking URL test successful');
        $.get(`/api/analytics?track_id=${trackId}`, function(data) {
          const track = data.find(t => t.track_id === trackId);
          showToast(`トラッキングリンクのテスト成功: クリック数=${track ? track.clicks : 0}`, 'success');
        }).fail(function(xhr) {
          console.error('❌ Failed to fetch click count:', xhr.status, xhr.statusText);
          showToast('クリック数確認に失敗しました', 'danger');
        });
      },
      error: function(xhr) {
        console.error('❌ Tracking URL test failed:', xhr.status, xhr.statusText);
        showToast('トラッキングリンクのテストに失敗しました', 'danger');
      }
    });
  });
  $modal.find('.copy-tracking-btn').off('click').on('click', function() {
    const text = $(this).data('clipboard-text');
    console.log('📋 Copying tracking URL from modal:', text);
    navigator.clipboard.writeText(text).then(() => {
      console.log('✅ Copied to clipboard');
      showToast('トラッキングリンクをクリップボードにコピーしました', 'success');
    }).catch(err => {
      console.error('❌ Clipboard copy error:', err);
      showToast('コピーに失敗しました', 'danger');
    });
  });
  $modal.modal('show');
}

// Iframeプレビューの更新
function updateIframePreview() {
  console.log('🔄 Updating iframe preview');
  const htmlContent = $('#html-content').val() || quill?.root?.innerHTML || '';
  if (!htmlContent.trim()) {
    console.warn('⚠️ No HTML content for preview');
    $('#template-preview').contents().find('body').html('<p>プレビューがありません</p>');
    return;
  }
  const replacedContent = htmlContent
    .replace('{{name}}', 'サンプル')
    .replace('{{role}}', '営業')
    .replace('{{email}}', 'sample@example.com')
    .replace('{{department}}', '営業部')
    .replace('{{company}}', '株式会社サンプル')
    .replace('{{phone}}', '03-1234-5678')
    .replace('{{address}}', '東京都渋谷区1-2-3')
    .replace('{{website}}', 'https://example.com')
    .replace('{{linkedin}}', 'https://linkedin.com/in/sample')
    .replace('{{banner_url}}', $('#banner-url').val() || 'https://placehold.co/468x60');
  try {
    const iframe = $('#template-preview')[0];
    const doc = iframe.contentDocument || iframe.contentWindow.document;
    doc.open();
    doc.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { font-family: Arial, sans-serif; padding: 10px; }
            img { max-width: 100%; height: auto; }
            a.tracking-link { color: #007bff; text-decoration: underline; cursor: pointer; }
          </style>
        </head>
        <body>${replacedContent}</body>
      </html>
    `);
    doc.close();
    $(doc).find('a.tracking-link').each(function() {
      const href = $(this).attr('href');
      const match = href.match(/\/api\/click\/([^\/]+)/);
      const trackId = match ? match[1] : null;
      if (trackId) {
        $(this).off('click').on('click', function(e) {
          e.preventDefault();
          console.log('🧪 Preview tracking link clicked:', href, 'Track ID:', trackId);
          $.ajax({
            url: `/api/click/${trackId}`,
            method: 'GET',
            success: function() {
              console.log('✅ Preview tracking link test successful');
              $.get(`/api/analytics?track_id=${trackId}`, function(data) {
                const track = data.find(t => t.track_id === trackId);
                showToast(`プレビューのトラッキングリンククリック成功: クリック数=${track ? track.clicks : 0}`, 'success');
              }).fail(function(xhr) {
                console.error('❌ Failed to fetch click count:', xhr.status, xhr.statusText);
                showToast('クリック数確認に失敗しました', 'danger');
              });
            },
            error: function(xhr) {
              console.error('❌ Preview tracking link test failed:', xhr.status, xhr.statusText);
              showToast('プレビューのトラッキングリンクテストに失敗しました', 'danger');
            }
          });
        });
      }
    });
    console.log('✅ Iframe preview updated');
  } catch (error) {
    console.error('❌ Error updating iframe preview:', error);
    showToast('プレビュー更新に失敗しました', 'danger');
  }
}

// テンプレートリストを取得
function loadTemplates() {
  console.log('📋 Loading templates');
  $.ajax({
    url: '/api/templates',
    method: 'GET',
    timeout: 5000,
    success: function(data) {
      templates = data;
      console.log('✅ Templates loaded:', data.length);

      // 🔽 テンプレート数を表示（例: <span id="template-count"></span>）
      $('#template-count').text(`テンプレート数: ${data.length}`);

      // テーブルを更新
      $('#template-list tbody').empty();
      data.forEach(t => {
        const formattedDate = formatToJST(t.created_at);
        const row = `
          <tr>
            <td>${escapeHtml(t.name)}</td>
            <td>${formattedDate}</td>
            <td>
              <button class="btn btn-sm btn-outline-primary edit-template" data-id="${t.id}">編集</button>
              <button class="btn btn-sm btn-outline-danger delete-template" data-id="${t.id}">削除</button>
            </td>
          </tr>
        `;
        $('#template-list tbody').append(row);
      });

      // イベント再バインド
      bindTemplateEditButtons();

      // テンプレート選択肢更新
      $('#template-ids').empty().append('<option value="">選択してください</option>');
      data.forEach(t => {
        $('#template-ids').append(`<option value="${t.id}">${escapeHtml(t.name)}</option>`);
      });
    },
    error: function(xhr) {
      console.error('❌ Template load failed:', xhr.status, xhr.statusText);
      showToast('テンプレートの取得に失敗しました', 'danger');
    }
  });
}



// キャンペーンリストを取得
function loadCampaigns() {
  console.log('📅 Loading campaigns');
  $.ajax({
    url: '/api/campaigns',
    method: 'GET',
    timeout: 5000,
    success: function(data) {
      console.log('✅ Campaigns loaded:', data.length);
      campaigns = data; // グローバル変数に格納

      $('#campaign-list tbody').empty();
      data.forEach(c => {
        if (!c.template_names || c.template_names.length === 0) return;

        const startDate = formatToJST(c.start_date);
        const endDate = formatToJST(c.end_date);
        const templateNames = c.template_names.join(', ');
        const row = `
          <tr>
            <td>${escapeHtml(templateNames)}</td>
            <td>${escapeHtml(c.department || '全て')}</td>
            <td>${startDate}</td>
            <td>${endDate}</td>
            <td>

              <button class="btn btn-outline-danger btn-sm delete-campaign" data-id="${c.id}">削除</button>
            </td>
          </tr>
        `;
        $('#campaign-list tbody').append(row);
      });
    },
    error: function(xhr) {
      console.error('❌ Campaign load failed:', xhr.status, xhr.statusText);
      showToast('キャンペーンの取得に失敗しました', 'danger');
    }
  });
}


// 部署オプションの読み込み
function loadDepartmentOptions() {
  console.log('🏢 Loading department options');
  $.ajax({
    url: '/api/departments',
    method: 'GET',
    timeout: 5000,
    success: function(res) {
      if (!res.success || !res.departments) {
        showToast(res.message || '部署一覧の取得に失敗しました', 'danger');
        return;
      }
      const $select = $('#department');
      $select.empty().append('<option value="">選択してください</option>');
      res.departments.forEach(dept => {
        $select.append(`<option value="${dept}">${escapeHtml(dept)}</option>`);
      });
      console.log('✅ Department options loaded:', res.departments.length);
    },
    error: function(xhr) {
      console.error('❌ Department load failed:', xhr.status, xhr.statusText);
      showToast('部署一覧の取得に失敗しました', 'danger');
    }
  });
}








function updateEmployeeTable(tracks) {
  console.log('🧑‍💼 updateEmployeeTable 呼び出し');
  console.log('👥 受信データ数:', tracks.length);

  const tbody = $('#employee-analytics-table tbody');
  tbody.empty();

  if (tracks.length === 0) {
    console.log('🚫 データなし → 表・グラフ非表示');
    $('#employee-table-wrapper').hide();
    $('#no-employee-data').show();
    return;
  }

  // データあり → 表示
  $('#employee-table-wrapper').show();
  $('#no-employee-data').hide();

  const countByEmployee = {};
  tracks.forEach(row => {
    const name = row.employee_name || '不明';
    const dept = row.department || '不明';
    const key = `${name}||${dept}`;
    countByEmployee[key] = (countByEmployee[key] || 0) + 1;
  });

  Object.entries(countByEmployee).forEach(([key, count]) => {
    const [name, dept] = key.split('||');
    const row = `<tr><td>${name}</td><td>${dept}</td><td>${count}</td></tr>`;
    tbody.append(row);
  });

  // グラフ描画
  const ctx = document.getElementById('employeeChart').getContext('2d');
  if (window.employeeChart) window.employeeChart.destroy();
  const labels = Object.keys(countByEmployee).map(k => k.split('||')[0]);
  const data = Object.values(countByEmployee);

  window.employeeChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'クリック数',
        data: data,
        backgroundColor: 'rgba(54, 162, 235, 0.5)'
      }]
    },
    options: {
      responsive: true,
      scales: {
        y: { beginAtZero: true }
      }
    }
  });
}












function updateClickHistoryTable(tracks) {
  console.log("📋 Updating click history table");
  const $tbody = $('#click-history-table tbody');
  $tbody.empty();

  console.log("📦 表に追加する件数:", tracks.length);
  tracks.forEach((t, i) => {
    console.log(`🔹 Row ${i + 1}:`, t);
    const row = `
      <tr>
        <td>${t.template_name || '不明'}</td>
        <td>${t.employee_name || '不明'}</td>
        <td>${t.department || '不明'}</td>
        <td>${t.clicked_at || ''}</td>
      </tr>
    `;
    $tbody.append(row);
  });
}



// A/Bテスト分析をロード
function loadAbTestAnalytics(startDate = '', endDate = '') {
  console.log('🧪 Loading A/B test analytics with', startDate, endDate);
  const params = { start_date: startDate, end_date: endDate };

  $.get('/api/analytics/abtest_summary', params, function(response) {
    const tableBody = $('#ab-test-table tbody');
    tableBody.empty();

    const data = response.data || [];
    if (data.length === 0) {
      tableBody.append('<tr><td colspan="3">データがありません。</td></tr>');
      $('#winner-banner').text('なし');
      return;
    }

    let maxClicks = 0;
    let winnerName = '不明';

    data.forEach(item => {
      tableBody.append(`
        <tr>
          <td>${item.template_name || '不明'}</td>
          <td>${item.clicks}</td>
          <td>${item.ctr ? item.ctr + '%' : '-'}</td>
        </tr>
      `);
      if (item.clicks > maxClicks) {
        maxClicks = item.clicks;
        winnerName = item.template_name || '不明';
      }
    });

    $('#winner-banner').text(winnerName);
  }).fail(function (xhr) {
    showToast('A/Bテスト分析データの取得に失敗しました', 'danger');
  });
}











// 社員別分析をロード
function loadEmployeeAnalytics(tracks = []) {
  tracks = Array.isArray(tracks) ? tracks : [];
  console.log('👤 Loading employee analytics with', tracks);

  const tbody = $('#employee-analytics-table tbody');
  tbody.empty();

  if (!tracks.length) {
    console.log('📦 データ件数: 0');
    $('#employee-table-wrapper').hide();
    $('#no-employee-data').show();

    if (window.employeeChart instanceof Chart) {
      window.employeeChart.destroy();
      window.employeeChart = null;

      const canvas = document.getElementById('employeeChart');
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }

    return;
  }

  $('#employee-table-wrapper').show();
  $('#no-employee-data').hide();

  const labels = [];
  const clickData = [];

  tracks.forEach(track => {
    const name = track.employee_name || '不明';
    const department = track.department || '不明';
    const clicks = track.clicks || 0;

    labels.push(name);
    clickData.push(clicks);

    tbody.append(`
      <tr>
        <td>${name}</td>
        <td>${department}</td>
        <td>${clicks}</td>
      </tr>
    `);
  });

  if (window.employeeChart instanceof Chart) {
    window.employeeChart.destroy();
  }

  const ctx = document.getElementById('employeeChart').getContext('2d');
  window.employeeChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'クリック数',
        data: clickData,
        backgroundColor: 'rgba(75, 192, 192, 0.5)'
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: { beginAtZero: true }
      }
    }
  });
}












// ビュー初期化
function initializeView(view, role) {
  console.log(`🔵 Initial view: ${view}, User role: ${role}`);
  $(document).ready(() => {
    const availableSections = $('.content-section').map((i, el) => el.id).get();
    const availableNavs = $('.nav-link[data-view]').map((i, el) => $(el).data('view')).get();
    console.log(`🔍 DOM loaded, checking for #${view}. Available sections:`, availableSections, 'Available navs:', availableNavs);

    $('.content-section').removeClass('active-section').addClass('hidden');
    $('.nav-link').removeClass('active');
    const $targetSection = $(`#${view}`);
    const $targetNav = $(`[data-view="${view}"]`);

    if ($targetSection.length && ($targetNav.length || view === 'employee-portal')) {
      $targetSection.addClass('active-section').removeClass('hidden');
      $targetNav.addClass('active');
      currentView = view;
      console.log(`✅ ${view}: visible=${!$targetSection.hasClass('hidden')}`);
      switch (view) {
        case 'dashboard':
          currentEmployeePage = 1;
          loadDashboard();
          break;
        case 'employee-portal':
          loadEmployeePortal();
          break;
        case 'template-editor':
          loadTemplateEditor();
          break;
        case 'campaign-manager':
          loadCampaignManager();
          break;
        case 'analytics':
          loadAnalytics();
          break;
        case 'signature-history':
          loadSignatureHistory();
          break;
        case 'profile-editor': // ✅ プロフィール編集追加
          loadProfileEditor();
          break;
      }
    } else {
      console.error(`❌ Initial section #${view} not found or nav link missing. Section exists: ${$targetSection.length}, Nav exists: ${$targetNav.length}`);
      showToast('管理者ページが見つかりませんでした。index.htmlを確認してください。', 'danger');

      const validSections = role === 'admin'
        ? ['dashboard', 'template-editor', 'campaign-manager', 'analytics', 'signature-history', 'employee-portal', 'profile-editor']
        : ['employee-portal', 'profile-editor'];

      console.log(`🔍 Attempting fallback. Valid sections for ${role}:`, validSections);

      for (let fallbackView of validSections) {
        const $fallbackSection = $(`#${fallbackView}`);
        const $fallbackNav = $(`[data-view="${fallbackView}"]`);
        if ($fallbackSection.length) {
          console.log(`🔄 Falling back to #${fallbackView}`);
          $fallbackSection.addClass('active-section').removeClass('hidden');
          $fallbackNav.addClass('active');
          currentView = fallbackView;
          switch (fallbackView) {
            case 'dashboard':
              currentEmployeePage = 1;
              loadDashboard();
              break;
            case 'employee-portal':
              loadEmployeePortal();
              break;
            case 'template-editor':
              loadTemplateEditor();
              break;
            case 'campaign-manager':
              loadCampaignManager();
              break;
            case 'analytics':
              loadAnalytics();
              break;
            case 'signature-history':
              loadSignatureHistory();
              break;
            case 'profile-editor':
              loadProfileEditor();
              break;
          }
          showToast(`代替ページ (${fallbackView}) を表示しました。管理者ページが表示されない場合は、index.htmlのテンプレートを確認してください。`, 'warning');
          return;
        }
      }

      console.error(`❌ No valid sections found for ${role}`);
      showToast('利用可能なページが見つかりませんでした。ログイン画面に移動します。', 'danger');
      $('#content').html('<div class="alert alert-danger">ページがロードできません。index.htmlを確認してください。</div>');
      setTimeout(() => redirectToAuth('有効なページが見つかりませんでした。'), 3000);
    }
  });
}

// jQueryロード確認
if (typeof jQuery === 'undefined') {
  console.error('❌ jQuery is not loaded in script.js');
} else {
  $(document).ready(function () {
    if (window.initial_view) {
      showView(window.initial_view);
    }

    console.log('🔵 script.js initialized');
    console.log('🔵 jQuery version:', $.fn.jquery);

    // Flatpickrの初期化
if ($('#date-range').length) {
  flatpickr('#date-range', {
    mode: 'range',
    dateFormat: 'Y-m-d H:i:S',
    enableTime: true,
    time_24hr: true,
    locale: 'ja'
  });
  console.log('✅ Flatpickr initialized for #date-range');
}

if ($('#filter-start-date').length) {
  flatpickr('#filter-start-date', {
    dateFormat: 'Y-m-d',
    locale: 'ja'
  });
  console.log('✅ Flatpickr initialized for #filter-start-date');
}

if ($('#filter-end-date').length) {
  flatpickr('#filter-end-date', {
    dateFormat: 'Y-m-d',
    locale: 'ja'
  });
  console.log('✅ Flatpickr initialized for #filter-end-date');
}

// ✅ 絞り込みボタンクリックでAnalytics再読み込み
$('#apply-date-filter').on('click', function () {
  const startDate = $('#filter-start-date').val();
  const endDate = $('#filter-end-date').val();
  console.log('🔍 apply-date-filter clicked');
  console.log('📤 Sending to loadAnalytics:', startDate, endDate);
  loadAnalytics(startDate, endDate);
});


    // プレースホルダーボタンの生成
    const placeholders = ['{{name}}', '{{email}}', '{{department}}', '{{company}}', '{{phone}}', '{{address}}', '{{website}}', '{{linkedin}}'];
    const placeholderHtml = placeholders.map(p => `
      <button type="button" class="btn btn-outline-secondary btn-sm placeholder-btn me-1 mb-1" data-placeholder="${p}">${p}</button>
    `).join('');
    $('#placeholder-buttons').html(placeholderHtml);

    // プレースホルダーボタンのイベントリスナー
    $(document).on('click', '.placeholder-btn', handlePlaceholderInsert);

    // セッション確認
checkSession(function(isValid, sessionData) {
  if (!isValid) {
    console.warn('⚠️ Session invalid, redirecting to auth');
    redirectToAuth('ログインしてください。');
    return;
  }
  const userRole = sessionData?.user?.role || window.user_role || 'employee';
  console.log('🔵 Session data:', sessionData, 'User role:', userRole);

  // 👇 管理者なら employee-portal を削除
if (userRole === 'admin') {
  console.log('🧹 管理者なので employee-portal を削除します');
  console.log('🔍 Before removal - All navs:', $('.nav-link[data-view]').map((i, el) => $(el).data('view')).get());
  $('#employee-portal').remove();
  const $employeePortalNav = $('[data-view="employee-portal"]');
  if ($employeePortalNav.length) {
    $employeePortalNav.parent().remove();
    console.log('✅ Removed employee-portal nav');
  } else {
    console.log('⚠️ employee-portal nav not found');
  }
  console.log('🔍 After removal - All navs:', $('.nav-link[data-view]').map((i, el) => $(el).data('view')).get());
  console.log('🔍 Profile-editor section exists:', $('#profile-editor').length);
  console.log('🔍 Profile-editor nav exists:', $('[data-view="profile-editor"]').length);
}


  let initialView = window.initial_view || (userRole === 'admin' ? 'dashboard' : 'employee-portal');
  console.log('🔵 Initializing view:', initialView);
  initializeView(initialView, userRole);

      // フィルタ初期化
      $('#filter-name').val(employeeFilters.name);
      $('#filter-email').val(employeeFilters.email);
      $('#filter-department').val(employeeFilters.department);
      $('#filter-role').val(employeeFilters.role);
      $('#search-query').val(employeeFilters.search);
      updateSortIcons();

      // 社員フィルタフォーム送信
      $('#employee-filter-form').on('submit', function(e) {
        e.preventDefault();
        console.log('🔍 Applying employee filters');
        employeeFilters.name = $('#filter-name').val().trim();
        employeeFilters.email = $('#filter-email').val().trim();
        employeeFilters.department = $('#filter-department').val().trim();
        employeeFilters.role = $('#filter-role').val().trim();
        employeeFilters.search = $('#search-query').val().trim();
        currentEmployeePage = 1;
        localStorage.setItem('employeeFilters', JSON.stringify(employeeFilters));
        loadEmployees();
        updateSortIcons();
      });

      // フィルタリセット
      $('#reset-filters').on('click', function() {
        console.log('🔄 Resetting employee filters');
        employeeFilters = {
          name: '',
          email: '',
          department: '',
          role: '',
          search: '',
          sort: '',
          order: ''
        };
        localStorage.removeItem('employeeFilters');
        $('#employee-filter-form')[0].reset();
        currentEmployeePage = 1;
        loadEmployees();
        updateSortIcons();
      });

      // ソート
      $('.sortable').on('click', function() {
        const sortColumn = $(this).data('sort');
        console.log('🔢 Sorting by:', sortColumn);
        if (employeeFilters.sort === sortColumn) {
          employeeFilters.order = employeeFilters.order === 'asc' ? 'desc' : 'asc';
        } else {
          employeeFilters.sort = sortColumn;
          employeeFilters.order = 'asc';
        }
        currentEmployeePage = 1;
        localStorage.setItem('employeeFilters', JSON.stringify(employeeFilters));
        loadEmployees();
        updateSortIcons();
      });

// ナビゲーションクリック
$('.nav-link[data-view]').on('click', function (e) {
  e.preventDefault();
  const view = $(this).data('view');
  console.log('🟡 Nav link clicked:', view);

  // ✅ すでに表示されてる同一ビューならスキップ
  if (view === currentView && $(`#${view}`).is(':visible')) {
    console.log('🔄 Same view, skipping reload');
    return;
  }

  currentView = view;
  $('.nav-link').removeClass('active');
  $(this).addClass('active');
  $('.content-section').removeClass('active-section').addClass('hidden');
  const $section = $(`#${view}`);
  if ($section.length) {
    $section.addClass('active-section').removeClass('hidden');
    console.log(`✅ Section #${view}: visible=${!$section.hasClass('hidden')}`);
  } else {
    console.error(`❌ Section #${view} not found`);
    showToast('ページが見つかりませんでした。', 'danger');
    return;
  }

  try {
    switch (view) {
      case 'dashboard':
        currentEmployeePage = 1;
        loadDashboard();
        break;
      case 'employee-portal':
        loadEmployeePortal();
        break;
      case 'template-editor':
        loadTemplateEditor();
        break;
      case 'campaign-manager':
        loadCampaignManager();
        break;
      case 'analytics':
        loadAnalytics();
        break;
      case 'signature-history':
        loadSignatureHistory();
        break;
      case 'profile-editor': // ✅ プロフィール編集追加
        loadProfileEditor();
        break;
    }
  } catch (err) {
    console.error(`❌ Failed loading ${view}:`, err);
    showToast('ページ読み込みに失敗しました', 'danger');
  }
});


      // ページネーション
      $('#employee-pagination').on('click', '.page-link', function(e) {
        e.preventDefault();
        const page = $(this).data('page');
        console.log('🔢 Page link clicked:', page);
        if (page === 'prev' && currentEmployeePage > 1) {
          currentEmployeePage--;
        } else if (page === 'next') {
          currentEmployeePage++;
        } else if (typeof page === 'number') {
          currentEmployeePage = page;
        }
        loadEmployees();
      });

      // 分析タブ切り替え
$('[data-analytics-tab]').on('click', function (e) {
  e.preventDefault();
  console.log('🔵 Analytics tab clicked:', $(this).data('analytics-tab'));

  // タブのアクティブ状態を切り替え
  $('[data-analytics-tab]').removeClass('active');
  $(this).addClass('active');

  // 全てのタブコンテンツを非表示に
  $('.analytics-tab-content').addClass('hidden');

  // 対象のタブだけ表示
  const tab = $(this).data('analytics-tab');
  $(`#${tab}-tab`).removeClass('hidden');

  if (tab === 'abtest') {
    loadAbTestAnalytics();
  }

  // employee タブでのデータロードは不要ならコメントアウト
  // else if (tab === 'employee') {
  //   loadEmployeeAnalytics();
  // }
});


      // 社員編集
$('#employee-list').on('click', '.edit-employee-btn', function() {
  const id = $(this).data('id');
  console.log('✏️ Editing employee ID:', id);
  $.ajax({
    url: `/api/employees/${id}`,
    method: 'GET',
    success: function(data) {
      if (data.success && data.employee) {
        $('#edit-employee-id').val(data.employee.id);
        $('#edit-name').val(data.employee.name || '');
        $('#edit-email').val(data.employee.email || '');
        $('#edit-department').val(data.employee.department || '');
        $('#edit-role').val(data.employee.role || '');

        // 🔽 Bootstrap 5 のモーダル表示コードに修正
        const modal = new bootstrap.Modal(document.getElementById('editEmployeeModal'));
        modal.show();

        console.log('✅ Employee data loaded for editing');
      } else {
        console.error('❌ Failed to load employee data:', data.message);
        showToast(data.message || '社員データ取得に失敗しました', 'danger');
      }
    },
    error: function(xhr) {
      console.error('❌ Failed to get employee:', xhr.status, xhr.statusText);
      showToast('社員データ取得に失敗しました', 'danger');
    }
  });
});


      // 社員削除
      $('#employee-list').on('click', '.delete-employee-btn', function() {
        const id = $(this).data('id');
        console.log('🗑️ Deleting employee ID:', id);
        if (confirm('この社員を削除しますか？')) {
          $.ajax({
            url: `/api/employees/${id}`,
            method: 'DELETE',
            success: function(response) {
              console.log('✅ Employee deleted:', response);
              showToast(response.message || '社員が削除されました', 'success');
              loadEmployees();
            },
            error: function(xhr) {
              console.error('❌ Error deleting employee:', xhr.status, xhr.statusText);
              showToast(xhr.responseJSON?.message || '削除に失敗しました', 'danger');
            }
          });
        }
      });

      // 社員編集フォーム送信
$('#edit-employee-form').on('submit', function(e) {
  e.preventDefault();
  const id = $('#edit-employee-id').val();
  const csrfToken = $('meta[name="csrf_token"]').attr('content'); // ← metaタグと名前合わせてね！

  console.log('📤 Submitting edit employee form for ID:', id);
  $.ajax({
    url: `/api/employees/${id}`,
    method: 'POST',
    data: {
      name: $('#edit-name').val(),
      email: $('#edit-email').val(),
      department: $('#edit-department').val(),
      role: $('#edit-role').val()
    },
    headers: {
      'X-CSRF-Token': csrfToken
    },
    success: function(response) {
      console.log('✅ Employee updated:', response);
      showToast(response.message || '社員情報が更新されました', 'success');
      $('#editEmployeeModal').modal('hide');
      loadEmployees();
    },
    error: function(xhr) {
      console.error('❌ Update employee error:', xhr.status, xhr.statusText);
      showToast(xhr.responseJSON?.message || '更新に失敗しました', 'danger');
    }
  });
});


      // デバイスプレビュー切り替え
      $('.device-preview-btn').on('click', function() {
        const device = $(this).data('device');
        console.log('📱 Switching preview to:', device);
        $('.device-preview-btn').removeClass('active');
        $(this).addClass('active');
        const $iframe = $('#template-preview');
        if (device === 'desktop') {
          $iframe.css({ width: '100%', height: '400px' });
        } else if (device === 'tablet') {
          $iframe.css({ width: '768px', height: '400px' });
        } else if (device === 'mobile') {
          $iframe.css({ width: '375px', height: '400px' });
        }
        updateIframePreview();
      });






function fetchCurrentUser() {
  return new Promise((resolve, reject) => {
    $.get('/api/session', function (res) {
      if (res.success && res.user && res.user.id) {
        currentUserId = res.user.id;
        console.log('🟢 Logged-in user ID:', currentUserId);
        resolve();
      } else {
        console.warn('⚠️ ユーザー情報の取得に失敗しました');
        reject();
      }
    }).fail(err => {
      console.error('❌ セッション取得失敗:', err);
      reject();
    });
  });
}

function generateTrackingLink(originalUrl, fullMatch, updatedHtml, completed, matches, callback) {
  $.ajax({
    url: '/api/generate_track',
    method: 'POST',
    contentType: 'application/json',
    data: JSON.stringify({
      url: originalUrl,
      employeeId: currentUserId,
      templateId
    }),
    success: function (res) {
      if (res.success) {
        const newLink = `<a href="${res.track_url}" target="_blank">${res.track_url}</a>`;
        updatedHtml = updatedHtml.replace(fullMatch, newLink);
      }
      completed.count++;
      if (completed.count === matches.length) callback(updatedHtml);
    },
    error: function () {
      completed.count++;
      if (completed.count === matches.length) callback(updatedHtml);
    }
  });
}

function copyToClipboard(content) {
  console.log('📋 Calling copyToClipboard...');

  const plainText = content
    .replace(/<p[^>]*>/gi, '')              // <p> 開始タグを消す
    .replace(/<\/p>/gi, '\n')               // </p> → 改行
    .replace(/<br\s*\/?>/gi, '\n')          // <br> → 改行
    .replace(/<a [^>]*href="([^"]+)"[^>]*>.*?<\/a>/gi, '$1') // aタグ → hrefだけ
    .replace(/<[^>]+>/g, '')                // その他HTMLタグ除去
    .replace(/&nbsp;/g, ' ')                // HTML特殊文字
    .replace(/&amp;/g, '&')
    .trim();

  navigator.clipboard.writeText(plainText).then(() => {
    console.log('✅ Successfully copied to clipboard');
    showToast('クリップボードにコピーされました', 'success');
  }).catch(err => {
    console.error('❌ Clipboard copy failed:', err);
    showToast('コピーに失敗しました', 'danger');
  });
}



$(document).ready(() => {
  fetchCurrentUser().then(() => {
    $('.copy-btn').on('click', function () {
      const target = $(this).data('target');
      const $target = $(target);
      const templateId = document.querySelector('#employee-portal')?.dataset.templateId || '';

      if (!$target.length || !currentUserId || !templateId) {
        showToast('コピー対象またはIDが取得できません', 'danger');
        return;
      }

      if (target === '#html-signature') {
        const html = $target.html();
        const linkRegex = /<a[^>]+href=["'](https?:\/\/[^"']+)["'][^>]*>(.*?)<\/a>/gi;
        const matches = [...html.matchAll(linkRegex)];

        if (matches.length === 0) {
          copyToClipboard(html);
          return;
        }

        let updatedHtml = html;
        const completed = { count: 0 };

        matches.forEach(match => {
          const fullMatch = match[0];
          const href = match[1];
          const isTracked = href.includes('/api/click/');

          if (isTracked) {
            completed.count++;
            if (completed.count === matches.length) copyToClipboard(updatedHtml);
          } else {
            generateTrackingLink(href, fullMatch, updatedHtml, completed, matches, copyToClipboard);
          }
        });
      } else {
        const content = $target.is('input, textarea') ? $target.val() : $target.text();
        copyToClipboard(content);
      }
    });
  });
});





// テンプレート編集
$('#template-list').on('click', '.edit-template', function () {
  const id = $(this).data('id');
  editTemplate(id);
});

// テンプレート削除
$('#template-list').on('click', '.delete-template', function () {
  const id = $(this).data('id');
  deleteTemplate(id);
});

// トラッキングURL生成ボタン
$('#generate-track-btn').on('click', handleGenerateTrack);

    });
  });
}

// ダッシュボードの読み込み
function loadDashboard() {
  console.log('📊 Loading dashboard');
  setTimeout(() => loadTemplates(), 100);
  setTimeout(() => loadCampaigns(), 200);
  setTimeout(() => loadEmployees(), 300);

  // 🔽 templates数だけ正確なエンドポイントから取得
  let actualTemplateCount = 0;
  $.get('/api/templates', function(tdata) {
    actualTemplateCount = tdata.length;

    // 次に統計情報取得
    $.ajax({
      url: '/api/statistics',
      method: 'GET',
      timeout: 5000,
      success: function(data) {
        const stats = {
          templates: actualTemplateCount, // ← ここを修正
          clicks: data.reduce((sum, t) => sum + (t.clicks || 0), 0),
          employees: new Set(data.map(t => t.employee_name)).size
        };
        $('#stats-content').html(`
          <p>テンプレート数: ${stats.templates}</p>
          <p>総クリック数: ${stats.clicks}</p>
          <p>関与社員数: ${stats.employees}</p>
        `);
        console.log('✅ Statistics loaded:', stats);
      },
      error: function(xhr) {
        console.error('❌ Failed to load statistics:', xhr.status, xhr.statusText);
        showToast(xhr.responseJSON?.message || '統計データの取得に失敗しました', 'danger');
      }
    });
  });

  // CSVアップロードのイベント処理
  $('#employee-import-form').off('submit').on('submit', function(e) {
    e.preventDefault();
    console.log('📤 Submitting CSV import form');
    const formData = new FormData(this);
    if (!formData.get('file')) {
      console.error('❌ No file selected');
      showToast('ファイルを選択してください', 'danger');
      return;
    }
    $.ajax({
      url: '/api/employees/import',
      method: 'POST',
      data: formData,
      processData: false,
      contentType: false,
      success: function(response) {
        console.log('✅ CSV import successful:', response);
        showToast(response.message || 'インポートが成功しました', 'success');
        currentEmployeePage = 1;
        loadEmployees();
      },
      error: function(xhr) {
        console.error('❌ CSV import error:', xhr.status, xhr.statusText);
        showToast(xhr.responseJSON?.message || 'インポートに失敗しました', 'danger');
      }
    });
  });
}


// 社員リストの取得
function loadEmployees() {
  console.log(`📋 Loading employees: page ${currentEmployeePage}`);
  const params = new URLSearchParams();
  params.append('page', currentEmployeePage);
  if (employeeFilters.name) params.append('filter_name', employeeFilters.name);
  if (employeeFilters.email) params.append('filter_email', employeeFilters.email);
  if (employeeFilters.department) params.append('filter_department', employeeFilters.department);
  if (employeeFilters.role) params.append('filter_role', employeeFilters.role);
  if (employeeFilters.search) params.append('search', employeeFilters.search);
  if (employeeFilters.sort) {
    params.append('sort_by', employeeFilters.sort);
    params.append('sort_order', employeeFilters.order);
  }
  console.log('🔵 Query params:', params.toString());

  $.ajax({
    url: `/api/employees?${params.toString()}`,
    method: 'GET',
    timeout: 5000,
    success: function(data) {
      if (!data.success) {
        console.error('❌ Failed to load employees:', data.message);
        showToast('社員データの取得に失敗しました', 'danger');
        $('#employee-list tbody').html('<tr><td colspan="5" class="text-center">データがありません</td></tr>');
        $('#employee-pagination').html('');
        return;
      }

      const employees = data.employees;
      const totalEmployees = data.total;
      const pages = data.pages;
      let html = '';

      if (employees.length === 0) {
        html = '<tr><td colspan="5" class="text-center">データがありません</td></tr>';
      } else {
        html = employees.map(e => `
          <tr>
            <td>${escapeHtml(e.name || '')}</td>
            <td>${escapeHtml(e.email || '')}</td>
            <td>${escapeHtml(e.department || '-')}</td>
            <td>${escapeHtml(e.role || '')}</td>
            <td>
              <button class="btn btn-sm btn-outline-primary edit-employee-btn" data-id="${e.id}">編集</button>
              <button class="btn btn-sm btn-outline-danger delete-employee-btn" data-id="${e.id}">削除</button>
            </td>
          </tr>
        `).join('');
      }

      $('#employee-list tbody').html(html);

      let pagination = '<ul class="pagination">';
      if (pages > 0) {
        pagination += `
          <li class="page-item ${currentEmployeePage === 1 ? 'disabled' : ''}">
            <a href="#" class="page-link" data-page="prev">Previous</a>
          </li>
        `;
        for (let i = 1; i <= pages; i++) {
          pagination += `
            <li class="page-item ${i === currentEmployeePage ? 'active' : ''}">
              <a href="#" class="page-link" data-page="${i}">${i}</a>
            </li>
          `;
        }
        pagination += `
          <li class="page-item ${currentEmployeePage === pages ? 'disabled' : ''}">
            <a href="#" class="page-link" data-page="next">Next</a>
          </li>
        `;
      }
      pagination += '</ul>';
      $('#employee-pagination').html(pagination);

      console.log('✅ Employees loaded:', employees.length, 'Total pages:', pages, 'Current page:', currentEmployeePage);

      // 署名履歴フィルタ用の社員リスト更新
      $('#filter-employee').empty().append('<option value="">全て</option>');
      employees.forEach(e => {
        $('#filter-employee').append(`<option value="${e.id}">${escapeHtml(e.name)}</option>`);
      });
    },
    error: function(xhr) {
      console.error('❌ Failed to load employees:', xhr.status, xhr.statusText);
      showToast('社員のデータ取得に失敗しました', 'danger');
      $('#employee-list tbody').html('<tr><td colspan="5" class="text-center">データがありません</td></tr>');
      $('#employee-pagination').html('');
    }
  });
}

// ソートアイコンの更新
function updateSortIcons() {
  $('.sortable').find('i').removeClass('fa-sort-up fa-sort-down').addClass('fa-sort');
  if (employeeFilters.sort && employeeFilters.order) {
    const $icon = $('.sortable').filter(`[data-sort="${employeeFilters.sort}"]`).find('i');
    console.log('🔢 Updating sort icon:', employeeFilters.sort, 'to', employeeFilters.order);
    $icon.removeClass('fa-sort').addClass(employeeFilters.order === 'asc' ? 'fa-sort-up' : 'fa-sort-down');
  }
}

// 🧹 仮リンクを除去する関数（ログ付き）
function sanitizeTemplateHTML(html) {
  const cleaned = html.replace(/<a[^>]+href=["']\{\{tracking_link_temp_[^"']+\}\}["'][^>]*>.*?<\/a>/gi, '');
  if (cleaned !== html) {
    console.warn('🧼 仮リンクを削除しました');
  } else {
    console.log('✅ 仮リンクは存在しませんでした');
  }
  return cleaned;
}

// ✏️ テンプレート編集
function editTemplate(id) {
  console.log('✏️ テンプレート編集開始 ID:', id);
  $.ajax({
    url: `/api/templates/${id}`,
    method: 'GET',
    timeout: 5000,
    success: function(data) {
      console.log('📥 テンプレートデータ受信:', data);
      if (!data.success || !data.template) {
        console.error('❌ テンプレートなし:', data?.message);
        showToast(data?.message || 'テンプレートが見つかりません', 'danger');
        return;
      }
      const template = data.template;
      $('#template-form').data('id', template.id);
      $('#template-name').val(template.name || '');
      $('#html-content').val(template.html_content || '');
      $('#text-content').val(template.text_content || '');
      $('#banner-url').val(template.banner_url || '');
      $('.nav-link[data-view="template-editor"]').click();

      setTimeout(() => {
        if (quill) {
          try {
            quill.setText('');
            quill.clipboard.dangerouslyPasteHTML(template.html_content || '');
            console.log('✅ Quill に HTML を反映完了');
          } catch (e) {
            console.error('❌ Quill HTML反映失敗:', e);
          }
        }
        updateIframePreview();
      }, 300);
      showToast('テンプレートが読み込まれました', 'success');
    },
    error: function(xhr) {
      console.error('❌ テンプレート取得失敗:', xhr.status, xhr.statusText);
      showToast(xhr.responseJSON?.message || 'テンプレートの取得に失敗しました', 'danger');
    }
  });
}

// 🗑️ テンプレート削除
function deleteTemplate(id) {
  console.log('🗑️ テンプレート削除開始 ID:', id);
  if (confirm('このテンプレートを削除しますか？')) {
    $.ajax({
      url: `/api/templates/${id}`,
      method: 'DELETE',
      success: function(response) {
        console.log('✅ 削除成功:', response);
        showToast(response.message || 'テンプレートを削除しました', 'success');
        loadDashboard();
      },
      error: function(xhr) {
        console.error('❌ 削除エラー:', xhr.status, xhr.statusText);
        showToast(xhr.responseJSON?.message || 'テンプレートの削除に失敗しました', 'danger');
      }
    });
  }
}

// 🧑‍💻 テンプレートエディタ初期化・保存
function loadTemplateEditor(template = null) {
  console.log('📝 テンプレートエディタ読み込み開始');

  const $section = $('#template-editor');
  if (!$section.length) {
    console.error('❌ テンプレートエディタが見つかりません');
    showToast('テンプレートページが見つかりませんでした', 'danger');
    return;
  }
  $('.content-section').removeClass('active-section').addClass('hidden');
  $section.addClass('active-section').removeClass('hidden');

  const $form = $('#template-form');
  $form[0].reset();
  $form.removeData('id');
  $form.removeAttr('data-template-id');
  $('#html-content').val('');
  $('#text-content').val('');
  $('#banner-url').val('');
  $('#template-preview').contents().find('body').html('');
  $('#template-id-span').text('読み込み中...');

  if (!quill) {
    if (typeof Quill === 'undefined') {
      console.error('❌ Quill ライブラリ未ロード');
      showToast('エディタの初期化に失敗しました', 'danger');
      return;
    }
    quill = new Quill('#quill-editor', {
      theme: 'snow',
      placeholder: 'ここにHTML署名を入力してください',
      modules: {
        toolbar: [
          [{ header: [1, 2, 3, false] }],
          ['bold', 'italic', 'underline'],
          [{ list: 'ordered' }, { list: 'bullet' }],
          ['link', 'image'],
          ['clean']
        ]
      }
    });
    console.log('✅ Quill 初期化完了');
  } else {
    quill.off('text-change');
    quill.root.innerHTML = '';
    console.log('🔄 Quill リセット完了');
  }

  if (template) {
    console.log('🧩 テンプレートデータをQuillに反映中...');
    $('#template-name').val(template.name);
    $('#html-content').val(template.html_content);
    $('#text-content').val(template.text_content);
    $('#banner-url').val(template.banner_url || '');
    $('#template-preview').contents().find('body').html(template.html_content);
    quill.root.innerHTML = template.html_content;

    $form.attr('data-template-id', template.id);
    $form.data('id', template.id);
    $('#template-id-span').text(template.id ?? 'undefined');
    console.log(`📎 template.id 設定済み: ${template.id}`);
  }

  quill.on('text-change', () => {
    const rawHtml = quill.root.innerHTML;
    const cleanedHtml = sanitizeTemplateHTML(rawHtml);
    console.log('✏️ HTML内容を更新:', cleanedHtml);
    $('#html-content').val(cleanedHtml);
    updateIframePreview();
  });

  $('#template-form').off('submit').on('submit', function(e) {
    e.preventDefault();
    console.log('📤 テンプレート保存フォーム送信');

    let currentHtml = $('#html-content').val();
    const trackRegex = /<a href=\"https?:\/\/[^\"]*\/api\/click\/[^\"]+\"[^>]*>(.*?)<\/a>/g;

    if (trackRegex.test(currentHtml)) {
      console.log('🧽 HTML内のトラッキングURLを仮リンクに戻します');
      currentHtml = currentHtml.replace(trackRegex, function (match, linkText) {
        const placeholder = `{{tracking_link_temp_${Date.now()}}}`;
        return `<a href=\"${placeholder}\" target=\"_blank\">${linkText}</a>`;
      });
      $('#html-content').val(currentHtml);
      console.log('✅ 修正後HTML:', currentHtml);
    }

    const id = $(this).data('id');
    const url = id ? `/api/templates/${id}` : '/api/templates';
    const method = id ? 'PUT' : 'POST';

    const html = $('#html-content').val();
    console.log('💾 保存前HTML:', html);

    const data = {
      name: $('#template-name').val(),
      html_content: html,
      text_content: $('#text-content').val(),
      banner_url: $('#banner-url').val()
    };

    $.ajax({
      url: url,
      method: method,
      contentType: 'application/json',
      data: JSON.stringify(data),
      success: function(response) {
        console.log('✅ 保存成功:', response);
        showToast(response.message || 'テンプレートを保存しました', 'success');

        if (response.template_id || response.id) {
          const newId = response.template_id || response.id;
          $form.attr('data-template-id', newId);
          $form.data('id', newId);
          $('#template-id-span').text(newId);
          console.log(`🔁 保存後の template-id 更新: ${newId}`);
        }

        loadTemplates();
      },
      error: function(xhr) {
        console.error('❌ 保存失敗:', xhr.status, xhr.statusText, xhr.responseJSON);
        showToast(xhr.responseJSON?.message || 'テンプレートの保存に失敗しました', 'danger');
      }
    });
  });
}





// キャンペーン管理の読み込み
function loadCampaignManager() {
  console.log('📅 Loading campaign manager');
  $('.content-section').removeClass('active-section').addClass('hidden');
  $('#campaign-manager').addClass('active-section').removeClass('hidden');

  loadTemplates();
  loadDepartmentOptions();

  $('#campaign-form').off('submit').on('submit', function(e) {
    e.preventDefault();
    console.log('📤 Submitting campaign form');

    const editingId = $('#campaign-form').data('editing-id');
    const templateIds = $('#template-ids').val();
    const department = $('#department').val();

    // 📝 日付処理改良
    const rawDate = $('#date-range').val();
    let dateRange = [];

    if (rawDate.includes('から')) {
      dateRange = rawDate.split('から').map(s => s.trim());
    } else if (rawDate.includes(' to ')) {
      dateRange = rawDate.split(' to ').map(s => s.trim());
    } else if (rawDate) {
      dateRange = [rawDate.trim(), rawDate.trim()];
    } else {
      // 空のとき fallback
      showToast('日付範囲を選択してください', 'danger');
      return;
    }

    // 保険：1つしか取れなかったら同じ日をend_dateにする
    if (dateRange.length === 1) {
      dateRange.push(dateRange[0]);
    }

    const data = {
      template_ids: templateIds,
      department: department || null,
      start_date: dateRange[0],
      end_date: dateRange[1]
    };

    const method = editingId ? 'PUT' : 'POST';
    const url = editingId ? `/api/campaigns/${editingId}` : '/api/campaigns';

    $.ajax({
      url,
      method,
      contentType: 'application/json',
      data: JSON.stringify(data),
      success: function(response) {
        console.log('✅ Campaign saved:', response);
        showToast(response.message || (editingId ? 'キャンペーンを更新しました' : 'キャンペーンを作成しました'), 'success');
        $('#campaign-form')[0].reset();
        $('#campaign-form').removeData('editing-id');
        loadCampaigns();
      },
      error: function(xhr) {
        console.error('❌ Campaign save error:', xhr.status, xhr.statusText);
        showToast(xhr.responseJSON?.message || 'キャンペーンの保存に失敗しました', 'danger');
      }
    });
  });
}



function bindTemplateEditButtons() {
  $('.edit-template').off('click').on('click', function () {
    const templateId = $(this).data('id');
    console.log(`🛠️ 編集ボタン押下 - templateId: ${templateId}`);

    $.get(`/api/templates/${templateId}`, function (res) {
      console.log('📥 テンプレート取得完了:', res);

      if (res.success && res.template) {
        loadTemplateEditor(res.template);  // ✅ 正しく渡す
        showToast('テンプレートが読み込まれました', 'success');
      } else {
        showToast('テンプレートの取得に失敗しました', 'danger');
      }
    }).fail(function () {
      showToast('テンプレートの取得に失敗しました', 'danger');
    });
  });
}


function updateAnalyticsTables(data) {
  console.log('📋 updateAnalyticsTables 呼び出し: 件数', data.length);

  const $table = $('#click-history-table tbody');
  $table.empty(); // 既存行を削除

  if (!Array.isArray(data) || data.length === 0) {
    $table.append('<tr><td colspan="4">データがありません</td></tr>');
    return;
  }

  data.forEach(item => {
    $table.append(`
      <tr>
        <td>${item.template_name || '不明'}</td>
        <td>${item.employee_name || '不明'}</td>
        <td>${item.department || '不明'}</td>
        <td>${item.clicked_at || '-'}</td>
      </tr>
    `);
  });
}






// Flatpickr初期化（日付ピッカーの設定）
flatpickr('#filter-start-date', {
    dateFormat: 'Y-m-d',
    defaultDate: new Date().setDate(new Date().getDate() - 7) // デフォルト: 7日前
});
flatpickr('#filter-end-date', {
    dateFormat: 'Y-m-d',
    defaultDate: new Date() // デフォルト: 今日
});

// 社員別グラフとテーブルの更新
function updateEmployeeChart(data) {
    console.log('📊 Updating employee chart with data:', data);
    // 既存のグラフを破棄
    if (employeeChart) {
        employeeChart.destroy();
        employeeChart = null;
    }
    // キャンバスをクリア
    const canvas = $('#employeeChart')[0];
    if (canvas) {
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
    // テーブルをクリア
    $('#employee-analytics-table tbody').empty();
    $('#no-employee-data').show();
    $('#employeeChart').hide();
    // 空データの場合
    if (!data || !Array.isArray(data) || data.length === 0) {
        console.log('⚠️ No employee data to display');
        $('#employee-analytics-table tbody').append('<tr><td colspan="3" class="text-center">データがありません</td></tr>');
        return;
    }
    // データがある場合
    $('#no-employee-data').hide();
    $('#employeeChart').show();
    data.forEach(row => {
        $('#employee-analytics-table tbody').append(`
            <tr>
                <td>${row.employee_name || '不明'}</td>
                <td>${row.department || '不明'}</td>
                <td>${row.clicks || 0}</td>
            </tr>
        `);
    });
    try {
        employeeChart = new Chart($('#employeeChart'), {
            type: 'bar',
            data: {
                labels: data.map(row => row.employee_name || '不明'),
                datasets: [{
                    label: 'クリック数',
                    data: data.map(row => row.clicks || 0),
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: true } }
            }
        });
        console.log('✅ Employee chart updated successfully');
    } catch (error) {
        console.error('❌ Error creating employee chart:', error);
        showToast('社員グラフの描画に失敗しました', 'error');
    }
}

// 時間帯グラフの更新（A/Bテスト、正常動作のため最小限のログ追加）
function updateTimebandChart(data) {
    console.log('📊 Updating timeband chart with data:', data);
    if (timebandChart) {
        timebandChart.destroy();
        timebandChart = null;
    }
    const canvas = $('#timebandChart')[0];
    if (canvas) {
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
    $('#no-timeband-data').show();
    $('#timebandChart').hide();
    if (!data.timebands || Object.keys(data.timebands).length === 0) {
        console.log('⚠️ No timeband data to display');
        return;
    }
    $('#no-timeband-data').hide();
    $('#timebandChart').show();
    const labels = Object.keys(data.timebands).sort();
    const values = labels.map(time => data.timebands[time]);
    try {
        timebandChart = new Chart($('#timebandChart'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'クリック数',
                    data: values,
                    fill: false,
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: true } }
            }
        });
        console.log('✅ Timeband chart updated successfully');
    } catch (error) {
        console.error('❌ Error creating timeband chart:', error);
        showToast('時間帯グラフの描画に失敗しました', 'error');
    }
}

// 部署別グラフとテーブルの更新
function updateDepartmentChart(data) {
    console.log('📊 Updating department chart with data:', data);
    // 既存のグラフを破棄
    if (departmentChart) {
        departmentChart.destroy();
        departmentChart = null;
    }
    // キャンバスをクリア
    const canvas = $('#departmentChart')[0];
    if (canvas) {
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
    // テーブルをクリア
    $('#department-table tbody').empty();
    $('#no-department-data').show();
    $('#departmentChart').hide();
    // 空データの場合
    if (!data || !Array.isArray(data) || data.length === 0) {
        console.log('⚠️ No department data to display');
        $('#department-table tbody').append('<tr><td colspan="2" class="text-center">データがありません</td></tr>');
        return;
    }
    // データがある場合
    $('#no-department-data').hide();
    $('#departmentChart').show();
    data.forEach(row => {
        $('#department-table tbody').append(`
            <tr>
                <td>${row.department || '不明'}</td>
                <td>${row.clicks || 0}</td>
            </tr>
        `);
    });
    try {
        departmentChart = new Chart($('#departmentChart'), {
            type: 'bar',
            data: {
                labels: data.map(row => row.department || '不明'),
                datasets: [{
                    label: 'クリック数',
                    data: data.map(row => row.clicks || 0),
                    backgroundColor: 'rgba(153, 102, 255, 0.2)',
                    borderColor: 'rgba(153, 102, 255, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: true } }
            }
        });
        console.log('✅ Department chart updated successfully');
    } catch (error) {
        console.error('❌ Error creating department chart:', error);
        showToast('部署グラフの描画に失敗しました', 'error');
    }
}

function loadAnalytics(startDate, endDate) {
    console.log('📊 loadAnalytics 呼び出し');
    console.log('🕵️‍♂️ 送信する startDate:', startDate);
    console.log('🕵️‍♀️ 送信する endDate:', endDate);

    const params = { start_date: startDate, end_date: endDate, _t: new Date().getTime() };

    // 時間帯データ
    $.ajax({
        url: '/api/timeband',
        data: params,
        timeout: 10000,
        cache: false,
        success: function(response) {
            console.log('Timeband data:', response);
            updateTimebandChart(response);
        },
        error: function(xhr, status, error) {
            console.error('❌ Failed loading timeband:', status, error);
            showToast('時間帯データの取得に失敗しました', 'error');
        }
    });

    // 部署別データ
$.ajax({
    url: '/api/analytics/department',
    data: params,
    timeout: 10000,
    cache: false,
    success: function(response) {
        console.log('Department analytics data:', response);
        updateDepartmentChart(response.data);
    },
    error: function(xhr, status, error) {
        console.error('❌ Failed loading department analytics:', status, error);
        showToast('部署データの取得に失敗しました', 'error');
    }
});

// 社員別データ ← 修正済み！
$.get('/api/employee-analytics', params, function(employeeTracks) {
    console.log('👤 employee analytics fetched:', employeeTracks);
    loadEmployeeAnalytics(employeeTracks);
}).fail(function (xhr) {
    console.error('❌ /api/employee-analytics エラー:', xhr.status, xhr.statusText);
    showToast('社員データの取得に失敗しました', 'error');
});

}


// 日付絞り込みボタンのハンドラ
$('#apply-date-filter').off('click').on('click', function(e) {
    e.preventDefault();
    const startDate = $('#filter-start-date').val();
    const endDate = $('#filter-end-date').val();

    if (!startDate || !endDate) {
        showToast('日付範囲を選択してください', 'error');
        return;
    }

    console.log('🔍 apply-date-filter clicked');
    console.log('📤 Sending to loadAnalytics:', { startDate, endDate });
    loadAnalytics(startDate, endDate);
});

// タブ切り替えハンドラ
let isLoadingAnalytics = false; // ロード中のフラグ
$('.nav-link[data-analytics-tab]').off('click').on('click', function(e) {
    e.preventDefault();
    const $this = $(this);
    const tab = $this.attr('data-analytics-tab');
    $('.analytics-tab-content').addClass('hidden');
    $(`#${tab}-tab`).removeClass('hidden');
    $('.nav-link').removeClass('active');
    $this.addClass('active');

    // 分析タブの場合のみ、現在の日付でデータ更新
    if ((tab === 'employee' || tab === 'abtest' || tab === 'department') && !isLoadingAnalytics) {
        isLoadingAnalytics = true;
        const startDate = $('#filter-start-date').val() || new Date(new Date().setDate(new Date().getDate() - 7)).toISOString().split('T')[0];
        const endDate = $('#filter-end-date').val() || new Date().toISOString().split('T')[0];
        loadAnalytics(startDate, endDate);
        setTimeout(() => { isLoadingAnalytics = false; }, 1000); // 1秒後にリセット
    }
});



// 署名履歴の読み込み
function loadSignatureHistory() {
  console.log('📜 Loading signature history');
  $('.content-section').removeClass('active-section').addClass('hidden');
  $('#signature-history').addClass('active-section').removeClass('hidden');
  $('#history-filter-form').off('submit').on('submit', function(e) {
    e.preventDefault();
    console.log('🔍 Applying history filters');
    const params = new URLSearchParams();
    const employeeId = $('#filter-employee').val();
    const startDate = $('#filter-start-date').val();
    const endDate = $('#filter-end-date').val();
    if (employeeId) params.append('employee_id', employeeId);
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    $.ajax({
      url: `/api/signature_history?${params.toString()}`,
      method: 'GET',
      timeout: 5000,
      success: function(data) {
        console.log('✅ Signature history loaded:', data.length);
        $('#history-table tbody').empty();
        data.forEach(h => {
          const appliedAt = formatToJST(h.applied_at);
          $('#history-table tbody').append(`
            <tr>
              <td>${escapeHtml(h.employee_name || '不明')}</td>
              <td>${escapeHtml(h.template_name || '不明')}</td>
              <td>${appliedAt}</td>
            </tr>
          `);
        });
      },
      error: function(xhr) {
        console.error('❌ Signature history load failed:', xhr.status, xhr.statusText);
        showToast('署名履歴の取得に失敗しました', 'danger');
      }
    });
  });
  $('#history-filter-form').submit();
}


function loadProfileEditor() {
  console.log('🟢 Loading profile editor');

  // 他セクションを非表示にする
  $('.content-section').removeClass('active-section fixed-visible').each(function () {
    this.style.display = 'none';
  });

  // 親要素を強制表示
  $('#profile-editor').parents().each(function (_, el) {
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
      $(el).css({
        display: 'block',
        visibility: 'visible',
        opacity: 1
      });
    }
  });

  // セクション表示
  $('#profile-editor')
    .removeClass('hidden')
    .addClass('active-section fixed-visible')
    .css({
      display: 'block',
      visibility: 'visible',
      opacity: 1
    });

  const form = $('#profile-form');
  if (!form.length) {
    console.error('❌ profile-form が見つかりません');
    return;
  }

  // プロフィール情報を取得して埋め込む
  $.get('/api/profile')
    .done(function (profile) {
      if (!profile || !profile.id) {
        showToast('プロフィール情報が見つかりませんでした。', 'danger');
        return;
      }

      Object.entries(profile).forEach(([key, value]) => {
        if (['id', 'organization_id', 'password', 'password_confirm'].includes(key)) return;
        const input = form.find(`[name="${key}"]`);
        if (input.length) input.val(value ?? '');
      });

      // パスワード欄は毎回空に
      $('#password').val('');
      $('#password-confirm').val('');
    })
    .fail(function (jqXHR) {
      let msg = 'プロフィール情報の取得に失敗しました。';
      if (jqXHR.responseJSON?.error) msg = jqXHR.responseJSON.error;
      showToast(msg, 'danger');
    });

  // 保存処理
  form.off('submit').on('submit', function (e) {
    e.preventDefault();
    const formData = {};
    $(this).serializeArray().forEach(({ name, value }) => {
      formData[name] = value;  // ← すべて送信する
    });

    const password = $('#password').val().trim();
    const confirm = $('#password-confirm').val().trim();

    if (password || confirm) {
      if (password !== confirm) {
        showToast('パスワードが一致しません', 'danger');
        return;
      }
      if (password.length < 6) {
        showToast('パスワードは6文字以上にしてください', 'danger');
        return;
      }
      formData.password = password;
      formData.password_confirm = confirm;
    }

    $.ajax({
      url: '/api/profile',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(formData),
      headers: {
        'X-CSRF-Token': $('meta[name="csrf_token"]').attr('content')
      },
      success: function () {
        showToast('プロフィールを保存しました', 'success');
        $('#password').val('');
        $('#password-confirm').val('');
      },
      error: function (jqXHR) {
        let msg = 'プロフィールの保存に失敗しました。';
        if (jqXHR.responseJSON?.error) msg = jqXHR.responseJSON.error;
        showToast(msg, 'danger');
      }
    });
  });
}















// 社員ポータルの読み込み
function loadEmployeePortal() {
    console.log('👤 Loading employee portal');

    const container = document.querySelector("#employee-portal");
    const employeeId = container?.dataset.employeeId || "";
    const templateId = container?.dataset.templateId || "";

    console.log("📦 container.dataset:", container?.dataset);
    console.log("📦 templateId:", templateId);
    console.log("📦 employeeId:", employeeId);

    $('.content-section').removeClass('active-section').addClass('hidden');
    $('#employee-portal').addClass('active-section').removeClass('hidden');

    // ✅ employeeId と templateId を URL に追加して送信
$.ajax({
    url: `/api/employee/signature`,  // ← employee_id/template_id を渡す必要なし
    method: 'GET',
    timeout: 5000,
    success: function(data) {
        console.log('🔵 Signature response:', data);
        if (data.success && data.signature) {
            $('#html-signature').html(data.signature.html_content || '<p>署名がありません</p>');
            $('#text-signature').text(data.signature.text_content || '署名がありません');
            $('#signature-error').addClass('hidden');
            console.log('✅ Signature loaded');
        } else {
            console.warn('⚠️ No signature found:', data.message);
            $('#signature-error').text(data.message || '署名が見つかりませんでした').removeClass('hidden');
            $('#html-signature').html('<p>署名がありません</p>');
            $('#text-signature').text('署名がありません');
        }
    },
    error: function(xhr) {
        console.error('❌ Signature load failed:', xhr.status, xhr.statusText, xhr.responseJSON);
        const errorMsg = xhr.status === 404
            ? '署名エンドポイントが見つかりません。サーバーの /api/employee/signature ルートを確認してください。'
            : xhr.responseJSON?.message || '署名の取得に失敗しました';
        $('#signature-error').text(errorMsg).removeClass('hidden');
        $('#html-signature').html('<p>署名がありません</p>');
        $('#text-signature').text('署名がありません');
        showToast(errorMsg, 'danger');
    }
});

}
