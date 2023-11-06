document.addEventListener('DOMContentLoaded', (event) => {
    // Initially hide all extended content and set button text appropriately
    document.querySelectorAll('[id^="content-"]').forEach(content => {
        content.style.display = 'none'; // Ensure the content is hidden initially
    });
    document.querySelectorAll('[id^="toggle-"]').forEach(button => {
        button.textContent = 'Read More'; // Ensure the button text is set to 'Read More' initially
    });

    // Add event listeners to toggle buttons
    document.querySelectorAll('[id^="toggle-"]').forEach(toggleButton => {
        toggleButton.addEventListener('click', () => {
            const messageId = toggleButton.getAttribute('data-message-id');
            toggleContent(messageId);
        });
    });

    // Add event listeners for message delete buttons
    document.querySelectorAll('[id^="delete-message-"]').forEach(deleteButton => {
    deleteButton.addEventListener('click', (event) => {
        event.stopPropagation(); // Prevent triggering comment delete
            const messageId = deleteButton.getAttribute('data-message-id');
            deleteMessage(messageId);
        });
    });

    // Add event listeners for comment delete buttons
    document.querySelectorAll('[id^="delete-comment-"]').forEach(deleteButton => {
    deleteButton.addEventListener('click', (event) => {
        event.stopPropagation(); // Stop the event from propagating
            const commentId = deleteButton.getAttribute('data-comment-id');
            deleteComment(event, commentId);
        });
    });
});


function toggleContent(id) {
    const content = document.getElementById('content-' + id);
    const button = document.getElementById('toggle-' + id);

    if (content.style.display === 'none') {
        content.style.display = 'inline'; // or 'block' depending on your layout
        button.textContent = 'Read Less';
    } else {
        content.style.display = 'none';
        button.textContent = 'Read More';
    }
}

function deleteMessage(messageId) {
    const confirmDelete = window.confirm("Are you sure you want to delete this post?");
    if (confirmDelete) {
        fetch(`/message/delete/${messageId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ message_id: messageId })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === "success") {
                window.location.href = '/'; // Redirect to the homepage
            } else {
                alert("Failed to delete post.");
            }
        });
    }
}


function deleteComment(event, commentId) {
    // Stop the event from bubbling up to parent elements
    event.stopPropagation();

    const confirmDelete = window.confirm("Are you sure you want to delete this comment?");
    if (confirmDelete) {
        // Your delete endpoint for comments. This also needs to be defined in your backend.
        fetch(`/comment/delete/${commentId}`, {
            method: 'POST'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.status === "success") {
                location.reload(); // Reload the page to reflect the changes
            } else {
                alert("Failed to delete comment.");
            }
        })
        .catch((error) => {
            console.error('There has been a problem with your fetch operation:', error);
        });
    }
}
