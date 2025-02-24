'use client';

export function GridBackground() {
  return (
    <div
      className="fixed inset-0 pointer-events-none"
      style={{
        background: 'radial-gradient(circle at center, #16A34AFF, #000000)',
      }}
    >
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px)
          `,
          backgroundSize: '20px 20px',
        }}
      />
    </div>
  );
}
