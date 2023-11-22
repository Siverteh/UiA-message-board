document.addEventListener('DOMContentLoaded', function() {
    var passwordInput = document.getElementById('password');
    var confirmPasswordInput = document.getElementById('confirm-password'); // Replace with the correct ID for your confirm password field
    var criteria = {
        length: document.getElementById('criteria-length'),
        special: document.getElementById('criteria-special'),
        lower: document.getElementById('criteria-lower'),
        upper: document.getElementById('criteria-upper'),
        number: document.getElementById('criteria-number'),
        match: document.getElementById('criteria-match')
    };

    function updateCriterion(criterion, isMet) {
        var icon = criterion.querySelector('.criteria-icon');
        icon.textContent = isMet ? '✔' : '✘';
        icon.style.color = isMet ? 'green' : 'red';
        criterion.style.color = isMet ? 'lightgray' : 'black';
    }

    function updateCriteria() {
        var passwordValue = passwordInput.value;
        var confirmPasswordValue = confirmPasswordInput.value;

        updateCriterion(criteria.length, passwordValue.length >= 8);
        updateCriterion(criteria.special, /[!@#$%^&*(),.?":{}|<>]/.test(passwordValue));
        updateCriterion(criteria.lower, /[a-z]/.test(passwordValue));
        updateCriterion(criteria.upper, /[A-Z]/.test(passwordValue));
        updateCriterion(criteria.number, /[0-9]/.test(passwordValue));
        updateCriterion(criteria.match, passwordValue && passwordValue === confirmPasswordValue);
    }

    passwordInput.addEventListener('input', updateCriteria);
    confirmPasswordInput.addEventListener('input', updateCriteria);
});
