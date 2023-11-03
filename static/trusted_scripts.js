// scripts.js
function deleteMessage(messageId) {
    const confirmDelete = window.confirm("Are you sure you want to delete this post?");
    if (confirmDelete) {
        // Your delete endpoint for articles. This needs to be defined in your backend.
        fetch(`/message/delete/${messageId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === "success") {
                window.location.href = "{{ url_for('index') }}";
            } else {
                alert("Failed to delete post.");
            }
        });
    }
}

function deleteComment(commentId) {
    const confirmDelete = window.confirm("Are you sure you want to delete this comment?");
    if (confirmDelete) {
        // Your delete endpoint for comments. This also needs to be defined in your backend.
        fetch(`/comment/delete/${commentId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === "success") {
                location.reload();
            } else {
                alert("Failed to delete comment.");
            }
        });
    }
}

function toggleContent(id) {
    let content = document.getElementById('content-' + id);
    let moreText = document.getElementById('more-' + id);
    if (content.style.display === "none") {
        content.style.display = "inline";
        moreText.textContent = "Read Less";
    } else {
        content.style.display = "none";
        moreText.textContent = "Read More";
    }
}

