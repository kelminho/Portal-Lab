// SecureCorp Portal — comportamento mínimo de interface, sem frameworks.
// A Content-Security-Policy proíbe scripts inline; todo JS fica neste arquivo
// e é ligado aos elementos por atributos data-*.
(function () {
    'use strict';

    // Confirmação para ações destrutivas: <form data-confirm="Mensagem">
    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(form.getAttribute('data-confirm'))) {
                event.preventDefault();
            }
        });
    });

    // Menu responsivo
    var toggle = document.querySelector('[data-nav-toggle]');
    var nav = document.querySelector('[data-nav]');
    if (toggle && nav) {
        toggle.addEventListener('click', function () {
            var open = nav.classList.toggle('open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
    }

    // Mensagens de sucesso desaparecem após alguns segundos
    document.querySelectorAll('[data-autodismiss]').forEach(function (element) {
        window.setTimeout(function () {
            element.classList.add('fade-out');
            window.setTimeout(function () { element.remove(); }, 400);
        }, 6000);
    });

    // Pré-validação do arquivo no navegador.
    // É apenas conveniência para o usuário: a validação real acontece no servidor.
    document.querySelectorAll('input[type="file"][data-max-bytes]').forEach(function (input) {
        var info = document.querySelector(input.getAttribute('data-info-target'));
        var maxBytes = parseInt(input.getAttribute('data-max-bytes'), 10);

        input.addEventListener('change', function () {
            var file = input.files && input.files[0];
            if (!info) {
                return;
            }

            if (!file) {
                info.textContent = '';
                input.setCustomValidity('');
                return;
            }

            var tooLarge = file.size > maxBytes;
            // textContent (e não innerHTML) evita interpretar o nome do arquivo como HTML.
            info.textContent = file.name + ' — ' + formatBytes(file.size) + (tooLarge ? ' (excede o limite)' : '');
            info.classList.toggle('field-error', tooLarge);
            input.setCustomValidity(tooLarge ? 'Arquivo excede o tamanho máximo permitido.' : '');
        });
    });

    function formatBytes(bytes) {
        var units = ['B', 'KB', 'MB', 'GB'];
        var size = bytes;
        var unit = 0;
        while (size >= 1024 && unit < units.length - 1) {
            size /= 1024;
            unit++;
        }
        return (Math.round(size * 10) / 10) + ' ' + units[unit];
    }
})();
