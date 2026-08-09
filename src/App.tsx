import './App.css';
import { EntriesScreen } from './features/entries/EntriesScreen';
import { VaultGate } from './features/vault/VaultGate';

function App() {
  return (
    <main className="app">
      <VaultGate>
        <EntriesScreen />
      </VaultGate>
    </main>
  );
}

export default App;
