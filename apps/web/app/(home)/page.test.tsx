import Page from '@/app/(home)/page';
import * as utils from '@repo/utils';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

describe('Page Component', () => {
  it('renders "Hello world"', () => {
    render(<Page />);
    expect(screen.getByText(/hello world/i)).toBeDefined();
  });

  it('renders formatted date from utils', () => {
    // Mock formatDate to control output
    const mockDate = 'Mocked Date';
    vi.spyOn(utils, 'formatDate').mockReturnValue(mockDate);

    render(<Page />);
    expect(screen.getByText(mockDate)).toBeDefined();
  });
});
