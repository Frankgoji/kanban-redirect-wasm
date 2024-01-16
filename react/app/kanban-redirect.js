import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom';

import { handle_redirect } from './tumblr_kanban_rust.js';

export const KanbanRedirect = (props) => {
    useEffect(() => {
        handle_redirect();
    }, []);

    return (
        <div className="root">
            <h1>Kanban Redirect</h1>
        </div>
    );
}
