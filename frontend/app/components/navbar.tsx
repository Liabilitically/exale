'use client';

export default function Navbar() {
  const logout = async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
  };

  return (
    <nav className="w-full p-4 flex justify-between bg-base-200 rounded">
      <h1 className="text-3xl font-bold px-4">Exale</h1>
      <button onClick={logout} className="btn btn-error btn-soft px-4 py-2 rounded">
        Logout
      </button>
    </nav>
  );
}