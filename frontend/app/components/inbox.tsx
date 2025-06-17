'use client';
import React, { useEffect, useState } from 'react';

interface Email {
  lead: boolean,
  drafted: boolean,
  subject: string;
  sender: string;
  snippet: string;
  timestamp: string;
}

const Inbox = () => {
  const [emails, setEmails] = useState<Object>({});
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [isFetching, setIsFetching] = useState<boolean>(true); // 🆕
  const [error, setError] = useState<boolean>(false);

  useEffect(() => {
    fetchEmails();
  }, []);

  const apiCallWithRetry = async (
    url: string,
    options: RequestInit,
    retry = true
  ): Promise<Response> => {
    const res = await fetch(url, { ...options, credentials: 'include' });

    if (res.status === 401 && retry) {
      const refreshed = await fetch('http://localhost:8000/refresh-token', {
        method: 'POST',
        credentials: 'include',
      });

      if (refreshed.ok) {
        return apiCallWithRetry(url, options, false);
      } else {
        throw new Error('Token refresh failed');
      }
    }

    return res;
  };

  const fetchEmails = async () => {
    try {
      setIsFetching(true); // 🆕 start spinner
      const res = await apiCallWithRetry('http://localhost:8000/read-emails', {
        method: 'POST',
      });

      if (!res.ok) throw new Error(`Error: ${res.status}`);

      const data = await res.json();
      setEmails(data);
    } catch (err) {
      console.error('Failed to fetch emails:', err);
      setError(true);
    } finally {
      setIsFetching(false); // 🆕 stop spinner
    }
  };

  const classify = async (email_id: string, email: Email) => {
    try {
      setLoadingId(email_id);

      const res = await apiCallWithRetry(
        'http://localhost:8000/draft',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            email: email.snippet,
            msg_id: email_id,
          }),
        }
      );

      if (!res.ok) throw new Error(`Error: ${res.status}`);
      const result = await res.json();
      console.log('AI result:', result);

      const button = document.getElementById(email_id);
      if (button) {
        button.setAttribute('disabled', 'disabled');
        button.innerText = 'Draft Created';
      }
    } catch (err) {
      console.error('Failed to classify email:', err);
    } finally {
      setLoadingId(null);
    }
  };

  const info_svg = (
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" className="bi bi-info-circle" viewBox="0 0 16 16">
      <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
      <path d="m8.93 6.588-2.29.287-.082.38.45.083c.294.07.352.176.288.469l-.738 3.468c-.194.897.105 1.319.808 1.319.545 0 1.178-.252 1.465-.598l.088-.416c-.2.176-.492.246-.686.246-.275 0-.375-.193-.304-.533zM9 4.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0"/>
    </svg>
  );

  if (isFetching) {
    return (
      <div className="flex items-start justify-center min-h-screen mt-4">
        <span className="loading loading-spinner loading-5xl text-accent" />
      </div>
    );
  } else if (error) {
    return (
      <div className='toast'>
        <div role='alert' className='alert alert-error font-bold items-center'>
          {info_svg}
          Unable to load emails. Please try again later.
        </div>
      </div>
    );
  }

  return (
    <ul className='pr-10 pl-15'>
      {Object.entries(emails).map(([email_id, email_details]) => (
        <li key={email_id} className="border-b border-b-base-100 py-2">
          <strong className='text-accent'>{email_details.subject}</strong> from {email_details.sender}
          <button
            onClick={() => classify(email_id, email_details)}
            className="btn btn-accent btn-soft mx-5 my-2"
            id={email_id}
            disabled={email_details.drafted}
          >
            {email_details.drafted ? "Draft Created" : "Draft Response"}
          </button>
          <div className='tooltip' data-tip="Click the button to draft a reply. You can view this draft in your Gmail account.">
            <button className='btn btn-circle btn-sm'>{info_svg}</button>
          </div>
          {loadingId === email_id && (
            <span className="loading loading-spinner loading-md text-accent pl-2" />
          )}
        </li>
      ))}
    </ul>
  );
};

export default Inbox;