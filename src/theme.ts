export const colors = {
  // Core brand (Gideon orange / amber)
  primary: '#F2A24A',        // main GIDEON logo + headers
  primaryLight: '#FFB866',   // hover / emphasis

  // Status
  success: '#3DDC84',        // terminal green (prompt, success)
  error: '#FF5F56',          // macOS red close button tone
  warning: '#F7C843',        // amber warning

  // Neutrals
  muted: '#A0A0A0',          // secondary text
  mutedDark: '#2A2A2A',      // panels / separators
  queryBg: '#1F1F1F',        // input / command area bg

  // Accents
  accent: '#F2A24A',         // same as primary for cohesion
  highlight: '#FFD28A',      // keyword highlights

  // Utility
  white: '#FFFFFF',
  info: '#6CB6FF',           // keep blue for links / info if needed

  // Optional persona color (if you still want named models)
  claude: '#E5896A',         // kept, but not used in Gideon UI
} as const;

export const dimensions = {
  boxWidth: 80,
  introWidth: 50,
} as const;

