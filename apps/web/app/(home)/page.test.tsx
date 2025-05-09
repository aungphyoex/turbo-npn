import Page from '@/app/(home)/page'; // Path to your Page component
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

// Mock the imported components
vi.mock('@repo/shadcn/mode-switcher', () => ({
  ModeSwitcher: () => <div>ModeSwitcher</div>,
}));

vi.mock('@repo/shadcn/video/player', () => ({
  VideoPlayer: ({
    poster,
    src,
    className,
  }: {
    poster: string;
    src: string;
    className: string;
  }) => (
    <div data-testid="video-player" className={className}>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={poster} alt="poster" />
      <video src={src} />
    </div>
  ),
}));

describe('Page Component', () => {
  it('renders ModeSwitcher and VideoPlayer components', () => {
    render(<Page />);

    // Check if ModeSwitcher is rendered
    expect(screen.getByText('ModeSwitcher')).toBeDefined();
    expect(screen.getByTestId('video-player')).toBeDefined();
  });
});
